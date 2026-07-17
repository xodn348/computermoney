//! fetch — buyer-side auto-pay for HTTP 402.
//!
//! The counterpart to `paywall`: GET a URL and, if the server answers 402 with
//! cm terms, pay the quoted Silent Payments code on-chain and retry with the
//! txid as proof. The agent never sees a key or an address — it asks for a
//! resource and gets it, and the payment happens underneath.
//!
//! Guards before any money moves: the terms must be for our network, `pay_to`
//! must be a Silent Payments code for it, and the price must be within the
//! caller's `max_sats` cap. The wallet's standing policy (amount cap, daily
//! window, blocklist) is then applied, because the amount is only known once
//! the 402 is read — the cap cannot live at the call site. The blocklist gates
//! the payee handle (the sp code); a silent payment's on-chain address is
//! one-time and cannot be pre-listed, so `pay::sp_send` additionally checks the
//! derived address as a uniform backstop.

use std::error::Error;
use std::thread::sleep;
use std::time::Duration;

use crate::ledger::{self, Ledger};
use crate::paywall::Terms;
use crate::policy;
use crate::storage;
use crate::wallet::Wallet;

/// How many times to re-GET with the payment proof before giving up, and the
/// gap between tries. Esplora sees the mempool within ~1 s, so a handful of
/// short retries covers propagation without a long stall.
const RETRIES: u32 = 5;
const RETRY_DELAY_SECS: u64 = 2;
/// Timeout for the initial GET, and a tighter one for each paid retry so the
/// whole pay-and-retry loop stays well inside a client's tool-call budget
/// (worst case ≈ FIRST + 5×(RETRY + delay), a bit over a minute, not minutes).
const FIRST_TIMEOUT_SECS: u64 = 15;
const RETRY_TIMEOUT_SECS: u64 = 10;

/// The result of a fetch: the final HTTP status, the response body, and (if a
/// payment was made) the txid and sats paid.
pub struct FetchOut {
    pub status: u16,
    pub body: String,
    pub paid: Option<(String, u64)>,
}

/// GET `url`, auto-paying a 402 up to `max_sats`. A 200 passes straight
/// through; a 402 triggers the pay-and-retry loop; any other status is an
/// error. `led` funds the payment and gates it on policy.
pub fn fetch(
    wallet: &Wallet,
    led: &mut Ledger,
    url: &str,
    max_sats: u64,
) -> Result<FetchOut, Box<dyn Error>> {
    // Reject non-web schemes before any network call — this tool fetches URLs an
    // agent supplies, and only http(s) is meaningful here.
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!("url must start with http:// or https:// (got {url})").into());
    }
    let first = http_get(url, None, FIRST_TIMEOUT_SECS)?;
    if first.status == 200 {
        return Ok(FetchOut { status: 200, body: first.body, paid: None });
    }
    if first.status != 402 {
        return Err(format!("GET {url} -> {} {}", first.status, snippet(&first.body)).into());
    }

    let terms: Terms = serde_json::from_str(&first.body)
        .map_err(|e| format!("402 body is not cm terms ({e}): {}", snippet(&first.body)))?;
    let net = storage::network_label();
    let is_mainnet = storage::network() == bitcoin::Network::Bitcoin;
    check_terms(&terms, max_sats, net, is_mainnet)?;

    // Standing wallet policy, same as `cm send` — the amount is only known now.
    let pol = policy::Policy::load()?;
    let spent = led.spent_since(ledger::now_unix().saturating_sub(policy::DAILY_WINDOW_SECS));
    pol.check_amount(terms.sats, spent)?;
    pol.check_address(&terms.pay_to)?;

    let (ext, int) = wallet.descriptors();
    eprintln!("cm fetch: paying {} sats to {} for {url}", terms.sats, terms.pay_to);
    let txid = crate::pay::sp_send(led, wallet, &ext, &int, &terms.pay_to, terms.sats, pol.max_fee_sats)?;

    for attempt in 1..=RETRIES {
        let retry = http_get(url, Some(&txid), RETRY_TIMEOUT_SECS)?;
        if retry.status == 200 {
            return Ok(FetchOut {
                status: 200,
                body: retry.body,
                paid: Some((txid, terms.sats)),
            });
        }
        if attempt < RETRIES {
            sleep(Duration::from_secs(RETRY_DELAY_SECS));
        }
    }
    Err(format!(
        "paid {} sats (txid {txid}) but {url} still returned 402 after {RETRIES} retries",
        terms.sats
    )
    .into())
}

/// Reject terms we must not pay: wrong version, wrong network, a `pay_to` that
/// is not a Silent Payments code for our network, or a price over the cap. The
/// network is passed in (not read from env) so the guard is unit-testable.
fn check_terms(terms: &Terms, max_sats: u64, net_label: &str, is_mainnet: bool) -> Result<(), Box<dyn Error>> {
    if terms.cm402 != 1 {
        return Err(format!("unsupported cm402 version {}", terms.cm402).into());
    }
    if terms.network != net_label {
        return Err(format!(
            "payment is for network {}, wallet is on {net_label}",
            terms.network
        )
        .into());
    }
    let want_hrp = if is_mainnet { "sp1" } else { "tsp1" };
    if !terms.pay_to.starts_with(want_hrp) {
        return Err(format!("pay_to {} is not a {want_hrp} silent-payment code", terms.pay_to).into());
    }
    if terms.sats > max_sats {
        return Err(format!("price {} sats exceeds max_sats {max_sats}", terms.sats).into());
    }
    Ok(())
}

struct Resp {
    status: u16,
    body: String,
}

fn http_get(url: &str, payment: Option<&str>, timeout_secs: u64) -> Result<Resp, Box<dyn Error>> {
    let mut req = minreq::get(url).with_timeout(timeout_secs);
    if let Some(txid) = payment {
        req = req.with_header("X-Payment", txid);
    }
    let resp = req.send()?;
    Ok(Resp {
        status: resp.status_code as u16,
        body: resp.as_str().unwrap_or("").to_string(),
    })
}

fn snippet(body: &str) -> String {
    let s: String = body.chars().take(120).collect();
    if body.len() > s.len() {
        format!("{s}…")
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms(network: &str, pay_to: &str, sats: u64) -> Terms {
        Terms { cm402: 1, sats, pay_to: pay_to.to_string(), network: network.to_string() }
    }

    #[test]
    fn accepts_well_formed_signet_terms() {
        let t = terms("signet", "tsp1qqexample", 300);
        assert!(check_terms(&t, 1000, "signet", false).is_ok());
    }

    #[test]
    fn rejects_network_mismatch() {
        let t = terms("mainnet", "sp1qexample", 300);
        let err = check_terms(&t, 1000, "signet", false).unwrap_err().to_string();
        assert!(err.contains("mainnet") && err.contains("signet"), "{err}");
    }

    #[test]
    fn rejects_over_cap_naming_both_numbers() {
        let t = terms("signet", "tsp1qqexample", 5000);
        let err = check_terms(&t, 1000, "signet", false).unwrap_err().to_string();
        assert!(err.contains("5000") && err.contains("1000"), "{err}");
    }

    #[test]
    fn rejects_hrp_mismatch() {
        // A mainnet-looking code offered to a signet wallet.
        let t = terms("signet", "sp1qmainnet", 300);
        let err = check_terms(&t, 1000, "signet", false).unwrap_err().to_string();
        assert!(err.contains("tsp1"), "{err}");
    }

    #[test]
    fn rejects_unknown_version() {
        let mut t = terms("signet", "tsp1qqexample", 300);
        t.cm402 = 2;
        assert!(check_terms(&t, 1000, "signet", false).is_err());
    }

    #[test]
    fn snippet_truncates_long_bodies() {
        let long = "x".repeat(500);
        let s = snippet(&long);
        assert!(s.ends_with('…'));
        assert!(s.chars().count() <= 121);
    }
}
