//! net — the payment protocol, transport-agnostic.
//!
//! WireGuard (`tunnel::FramedTunnel`) is the transport. The protocol logic
//! lives here behind a `Wire` seam and does not know which transport carries
//! its bytes — that is the coordination/settlement split made concrete. The
//! TCP `Wire` in the tests is a stand-in that proves the seam holds: swap the
//! transport, the payment logic above it does not move.

use std::error::Error;

use crate::chain;
use crate::ledger::{self, Entry, Ledger};
use crate::policy::{Policy, DAILY_WINDOW_SECS};
use crate::protocol::{Message, Receiver};

/// A bidirectional, message-framed channel. `recv` returns `None` when the
/// peer has gone (a TCP close, or a tunnel that went idle).
pub(crate) trait Wire {
    fn send(&mut self, msg: &Message) -> Result<(), Box<dyn Error>>;
    fn recv(&mut self) -> Result<Option<Message>, Box<dyn Error>>;
}

/// The receive side: answer AddrRequest with a fresh address, record each
/// issuance and each chain-verified receipt in the signed ledger (a Notify is
/// only a hint — we book the real on-chain amount, never the claimed one),
/// reconcile against the chain. Runs until the peer goes away.
pub(crate) fn run_receiver<W: Wire>(
    wire: &mut W,
    rx: &mut Receiver,
    led: &mut Ledger,
) -> Result<(), Box<dyn Error>> {
    // The index and address issued earlier in this session; a following Notify
    // triggers on-chain verification against that address. The chain is the only
    // proof of receipt — the Notify itself is never trusted.
    let mut issued_index: Option<u32> = None;
    let mut issued_address: Option<String> = None;
    while let Some(msg) = wire.recv()? {
        match msg {
            Message::AddrRequest { sats } => {
                if let Some(Message::AddrResponse { address, index }) =
                    rx.handle(Message::AddrRequest { sats })?
                {
                    led.append(Entry::AddressIssued { seq: led.next_seq(), index })?;
                    issued_index = Some(index);
                    issued_address = Some(address.clone());
                    eprintln!("[recv] issued index {index} for {sats} sats: {address}");
                    wire.send(&Message::AddrResponse { address, index })?;
                }
            }
            Message::Notify { txid, sats: claimed } => {
                // A Notify is an UNTRUSTED hint: a hostile payer could name any
                // confirmed txid and any amount. We never credit from the claim.
                // Instead we verify on-chain that this txid actually pays the
                // address we issued this session, and book the REAL amount the
                // chain reports. If the tx is not visible yet (mempool/esplora
                // lag) we record nothing — serve's periodic chain-watch books it
                // once it lands. Either way we return now: UDP has no close, so
                // reading on would block a full RECV_TIMEOUT and starve the next
                // buyer.
                let index = issued_index.unwrap_or(0);
                match &issued_address {
                    Some(addr) => match chain::deposits_to(addr) {
                        Ok(deposits) => match deposits.iter().find(|d| d.txid == txid) {
                            Some(d) => {
                                let booked = led.record_received(&d.txid, d.sats, index)?;
                                let _ = ledger::reconcile(led);
                                if booked {
                                    eprintln!(
                                        "[recv] verified {txid} pays {} sat to our address (claimed {claimed}); balance {} sats final",
                                        d.sats,
                                        led.balance()
                                    );
                                } else {
                                    eprintln!(
                                        "[recv] {txid} already recorded; balance {} sats final",
                                        led.balance()
                                    );
                                }
                            }
                            None => eprintln!(
                                "[recv] WARN notify {txid} does not pay our issued address (claimed {claimed} sat); ignoring — chain-watch will book it if it lands"
                            ),
                        },
                        Err(e) => eprintln!("[recv] WARN verifying notify {txid}: {e}"),
                    },
                    None => eprintln!(
                        "[recv] WARN notify {txid} with no address issued this session; ignoring"
                    ),
                }
                return Ok(());
            }
            Message::Chat { text } => eprintln!("[recv] chat: {text}"),
            Message::AddrResponse { .. } => {} // a client wouldn't send this
        }
    }
    Ok(())
}

/// The pay side: ask for an address, settle it on-chain, record the Sent
/// entry before notifying. A crash after broadcast still leaves the
/// payment on the work queue.
pub(crate) fn run_payer<W: Wire>(
    wire: &mut W,
    ext: &str,
    int: &str,
    led: &mut Ledger,
    sats: u64,
) -> Result<(), Box<dyn Error>> {
    // Policy: amount gates first, so an over-limit payment never even
    // contacts the peer.
    let policy = Policy::load()?;
    let spent_recent = led.spent_since(ledger::now_unix().saturating_sub(DAILY_WINDOW_SECS));
    policy.check_amount(sats, spent_recent)?;

    wire.send(&Message::AddrRequest { sats })?;
    let (address, index) = loop {
        match wire.recv()?.ok_or("peer closed before sending an address")? {
            Message::AddrResponse { address, index } => break (address, index),
            other => eprintln!("[pay] ignoring {other:?}"),
        }
    };
    eprintln!("[pay] address (index {index}): {address}");
    policy.check_address(&address)?; // OFAC blocklist, now that we know the destination

    eprintln!("[pay] syncing + building + broadcasting {sats} sats…");
    let txid = crate::pay::send(led, ext, int, &address, sats, policy.max_fee_sats)?;
    eprintln!("[pay] txid {txid}");

    wire.send(&Message::Notify { txid: txid.clone(), sats })?;
    println!("paid {sats} sats. watch it reach final (3 conf):");
    println!("  cm confs {txid}");
    println!("  {}", crate::storage::explorer_tx_url(&txid));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    const M: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Length-prefixed framing over a TCP stream — a `Wire` stand-in that
    /// proves the protocol logic is transport-agnostic.
    struct TcpWire {
        stream: TcpStream,
        buf: Vec<u8>,
    }

    impl TcpWire {
        fn new(stream: TcpStream) -> Self {
            Self { stream, buf: Vec::new() }
        }
    }

    impl Wire for TcpWire {
        fn send(&mut self, msg: &Message) -> Result<(), Box<dyn Error>> {
            self.stream.write_all(&msg.encode())?;
            Ok(())
        }

        fn recv(&mut self) -> Result<Option<Message>, Box<dyn Error>> {
            let mut tmp = [0u8; 4096];
            loop {
                if let Some((msg, consumed)) = Message::decode(&self.buf) {
                    self.buf.drain(..consumed);
                    return Ok(Some(msg));
                }
                let n = self.stream.read(&mut tmp)?;
                if n == 0 {
                    return Ok(None); // peer closed
                }
                self.buf.extend_from_slice(&tmp[..n]);
            }
        }
    }

    fn temp_ledger(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("cm_net_test_{tag}_{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn daemon_hands_out_a_fresh_address_and_records_it() {
        let ledger = temp_ledger("issue");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let ledger_for_thread = ledger.clone();

        // Server: accept one connection, run the receive protocol, exit.
        let server = std::thread::spawn(move || {
            let w = Wallet::from_mnemonic(M).unwrap();
            let mut led =
                Ledger::open_with_identity(&ledger_for_thread, w.signing_keypair().unwrap())
                    .unwrap();
            let mut rx = Receiver::new(&w, led.next_address_index());
            let (conn, _) = listener.accept().unwrap();
            let mut wire = TcpWire::new(conn);
            run_receiver(&mut wire, &mut rx, &mut led).unwrap();
        });

        // Client: ask for an address over the same wire framing, then close.
        let mut client = TcpWire::new(TcpStream::connect(addr).unwrap());
        client.send(&Message::AddrRequest { sats: 5_000 }).unwrap();
        let (address, index) = match client.recv().unwrap().unwrap() {
            Message::AddrResponse { address, index } => (address, index),
            other => panic!("expected an address, got {other:?}"),
        };
        drop(client); // closing lets the server's run_receiver return
        server.join().unwrap();

        let w = Wallet::from_mnemonic(M).unwrap();
        assert_eq!(index, 0);
        assert_eq!(address, w.address(0).unwrap().to_string());

        // The issuance is on disk and the index advanced.
        let led = Ledger::open_with_identity(&ledger, w.signing_keypair().unwrap()).unwrap();
        assert_eq!(led.entries().len(), 1);
        assert_eq!(led.next_address_index(), 1);
        std::fs::remove_file(&ledger).unwrap();
    }
}
