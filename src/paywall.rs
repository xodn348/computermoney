//! paywall — a minimal HTTP 402 seller endpoint.
//!
//! The lean cut of the "paid API" rail: a seller sells one body for a fixed
//! price with no account, no invoice, and no upstream service. A GET with no
//! valid payment gets HTTP 402 plus JSON terms carrying our static Silent
//! Payments code; the buyer pays on-chain and retries with `X-Payment: <txid>`;
//! we reconstruct the transaction, run the BIP-352 receive check against it
//! (`scan::tx_pays_me`), and if it pays us at least the price we hand back the
//! body. The path is ignored — this endpoint sells exactly one thing.
//!
//! v1 is demo-grade on purpose: the bare txid is a
//! third-party-observable proof, so a race-claim is possible; we blunt it with
//! a session-lifetime single-use set so one txid buys at most once. Delivery is
//! 0-conf and the transport is plain HTTP. The v2 proof spec (per-quote label +
//! schnorr payer proof + deliver-once cache) closes all three; none of it is
//! here.

use std::collections::HashSet;
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::scan;
use crate::storage;
use crate::wallet::Wallet;

/// The 402 terms body. `cm402` is a version tag (always 1); `pay_to` is our
/// static SP code; `network` is the wallet's network label so the buyer can
/// refuse to pay across networks. Shared with `fetch`, which parses it.
#[derive(Serialize, Deserialize)]
pub struct Terms {
    pub cm402: u8,
    pub sats: u64,
    pub pay_to: String,
    pub network: String,
}

/// A stalled or half-open client must not wedge the single accept loop, so cap
/// how long one connection may take to send its head or receive the response.
const IO_TIMEOUT_SECS: u64 = 10;

/// Serve `body` for `price_sats` on an already-bound `listener` until the process
/// exits. The listener is bound by the caller so a port conflict surfaces there
/// (a readable error) rather than in this thread. Blocking: the caller (a CLI
/// foreground command, or the MCP `cm_paywall` thread) owns the loop for the
/// session. Single-threaded — one buyer is served at a time, which is all a demo
/// needs and keeps the used-set trivially consistent.
pub fn run(
    listener: TcpListener,
    price_sats: u64,
    body: String,
    wallet: &Wallet,
) -> Result<(), Box<dyn Error>> {
    let sp_code = wallet.sp_code()?;
    let network = storage::network_label().to_string();
    let used: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
    let bind = listener.local_addr().map(|a| a.to_string()).unwrap_or_else(|_| "?".into());
    eprintln!("cm paywall: selling on {bind} for {price_sats} sats, pay_to {sp_code}");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = handle(s, price_sats, &body, &sp_code, &network, &used, wallet) {
                    eprintln!("cm paywall: request error: {e}");
                }
            }
            Err(e) => eprintln!("cm paywall: accept error: {e}"),
        }
    }
    Ok(())
}

/// A parsed request: only the method and the `X-Payment` header matter here.
struct Request {
    method: String,
    payment: Option<String>,
}

fn handle(
    mut stream: TcpStream,
    price_sats: u64,
    body: &str,
    sp_code: &str,
    network: &str,
    used: &Mutex<HashSet<String>>,
    wallet: &Wallet,
) -> Result<(), Box<dyn Error>> {
    // Bound both directions so a client that opens a socket and never finishes
    // its request (slowloris, or a dead peer) cannot park the accept loop. The
    // timeout surfaces as a read error, logged by the caller, and the
    // connection is dropped.
    let to = Some(Duration::from_secs(IO_TIMEOUT_SECS));
    stream.set_read_timeout(to)?;
    stream.set_write_timeout(to)?;
    let raw = read_headers(stream.try_clone()?)?;
    let req = parse_request(&raw);

    if req.method != "GET" {
        write_response(&mut stream, "405 Method Not Allowed", "text/plain", "GET only\n")?;
        return Ok(());
    }

    let paid = match req.payment.as_deref() {
        Some(txid) if is_txid(txid) => verify_payment(txid, price_sats, used, wallet),
        _ => false,
    };

    if paid {
        eprintln!("cm paywall: 200 paid ({}…)", &req.payment.unwrap()[..16]);
        write_response(&mut stream, "200 OK", "text/plain; charset=utf-8", body)?;
    } else {
        eprintln!("cm paywall: 402 (unpaid)");
        let terms = Terms {
            cm402: 1,
            sats: price_sats,
            pay_to: sp_code.to_string(),
            network: network.to_string(),
        };
        write_response(&mut stream, "402 Payment Required", "application/json", &serde_json::to_string(&terms)?)?;
    }
    Ok(())
}

/// Verify a claimed txid pays us at least the price and has not been redeemed
/// this session. Marks the txid used only on success, so one txid buys once.
/// A chain-lookup error is treated as "not paid" (the buyer can retry).
fn verify_payment(txid: &str, price_sats: u64, used: &Mutex<HashSet<String>>, wallet: &Wallet) -> bool {
    if used.lock().unwrap().contains(txid) {
        return false;
    }
    match scan::tx_pays_me(wallet, txid) {
        Ok(sats) if sats >= price_sats => {
            used.lock().unwrap().insert(txid.to_string());
            true
        }
        Ok(sats) => {
            eprintln!("cm paywall: {txid}… pays {sats} < {price_sats}, rejecting");
            false
        }
        Err(e) => {
            eprintln!("cm paywall: verify {txid} failed: {e}");
            false
        }
    }
}

/// Read the request head (up to and including the blank line) as one string.
/// Bodies are ignored; GET requests carry none.
fn read_headers(stream: TcpStream) -> std::io::Result<String> {
    let mut reader = BufReader::new(stream);
    let mut raw = String::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        let blank = line == "\r\n" || line == "\n";
        raw.push_str(&line);
        if n == 0 || blank {
            break;
        }
        // Bound the head so a hostile client cannot stream forever.
        if raw.len() > 8192 {
            break;
        }
    }
    Ok(raw)
}

/// Extract the method and any `X-Payment` header from a raw request head.
/// Header names are matched case-insensitively; the value is trimmed.
fn parse_request(raw: &str) -> Request {
    let mut lines = raw.split("\r\n");
    let first = lines.next().unwrap_or("");
    let method = first.split_whitespace().next().unwrap_or("").to_string();
    let mut payment = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("x-payment") {
                payment = Some(value.trim().to_string());
            }
        }
    }
    Request { method, payment }
}

/// A 64-character lowercase-or-uppercase hex string (a bitcoin txid).
fn is_txid(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn write_response(stream: &mut TcpStream, status: &str, content_type: &str, body: &str) -> std::io::Result<()> {
    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes())?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terms_serde_round_trip() {
        let t = Terms {
            cm402: 1,
            sats: 300,
            pay_to: "tsp1qqexample".to_string(),
            network: "signet".to_string(),
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: Terms = serde_json::from_str(&json).unwrap();
        assert_eq!(back.cm402, 1);
        assert_eq!(back.sats, 300);
        assert_eq!(back.pay_to, "tsp1qqexample");
        assert_eq!(back.network, "signet");
    }

    #[test]
    fn parses_method_and_payment_header() {
        let txid = "a".repeat(64);
        let raw = format!("GET /anything HTTP/1.1\r\nHost: x\r\nX-Payment: {txid}\r\n\r\n");
        let req = parse_request(&raw);
        assert_eq!(req.method, "GET");
        assert_eq!(req.payment.as_deref(), Some(txid.as_str()));
    }

    #[test]
    fn header_name_is_case_insensitive() {
        let txid = "b".repeat(64);
        let raw = format!("GET / HTTP/1.1\r\nx-PaYmEnT:   {txid}  \r\n\r\n");
        let req = parse_request(&raw);
        assert_eq!(req.payment.as_deref(), Some(txid.as_str()));
    }

    #[test]
    fn missing_payment_header_is_none() {
        let raw = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let req = parse_request(raw);
        assert_eq!(req.method, "GET");
        assert!(req.payment.is_none());
    }

    #[test]
    fn junk_payment_is_not_a_txid() {
        let raw = "GET / HTTP/1.1\r\nX-Payment: not-a-txid\r\n\r\n";
        let req = parse_request(raw);
        assert!(!is_txid(req.payment.as_deref().unwrap()));
        assert!(is_txid(&"9".repeat(64)));
        assert!(!is_txid(&"9".repeat(63)));
        assert!(!is_txid(&"g".repeat(64)));
    }

    #[test]
    fn non_get_method_detected() {
        let raw = "POST / HTTP/1.1\r\n\r\n";
        assert_eq!(parse_request(raw).method, "POST");
    }
}
