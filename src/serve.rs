//! serve — the seller's body: one resident daemon that never sleeps.
//!
//! `cm receive` was a one-shot: it pinned a single payer's key up front,
//! accepted exactly one tunnel, and exited. A real seller does three things
//! forever, so this collapses them into a single single-threaded loop:
//!
//!   - REPUBLISH — keep the DHT card fresh so buyers can still find us.
//!   - WATCH     — poll the chain for deposits with no live session (the
//!                 chain is the only proof of receipt) and advance pending
//!                 payments via the existing reconcile path.
//!   - ACCEPT    — answer any buyer's WireGuard handshake (key learned from
//!                 the handshake, not a CLI arg) and run the receive protocol.
//!
//! Why one loop and one process: the ledger is a single-writer file, so the
//! daemon takes an exclusive `lock_dir` for its whole life. It unlocks the
//! wallet once, opens the signed ledger once, and binds one UDP socket. The
//! loop's log lines are the operator UI — every duty prints one scannable
//! line. Sequential sessions are deliberate (lean): a crash at any point is
//! safe because the write-ahead ledger plus WATCH's reconcile recover state
//! on the next boot, so Ctrl-C is a legitimate way to stop.

use std::error::Error;
use std::net::UdpSocket;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::discover::{self, Card};
use crate::ledger::{self, Ledger};
use crate::net;
use crate::protocol::Receiver;
use crate::tunnel::FramedTunnel;
use crate::wallet::Wallet;
use crate::{chain, storage};

/// Refresh the DHT card this often; a stale card eventually falls out of the
/// DHT, so we re-put well inside its lifetime.
const REPUBLISH_INTERVAL: Duration = Duration::from_secs(45 * 60);
/// Poll the chain and reconcile pending payments this often.
const WATCH_INTERVAL: Duration = Duration::from_secs(60);
/// Socket read timeout: the accept blocks at most this long so the loop keeps
/// ticking its timers while idle instead of parking on `recv_from` forever.
const READ_TIMEOUT: Duration = Duration::from_secs(1);

/// Whether a periodic duty is due now: fires once at start (`last == None`)
/// and again every `interval` after its previous fire. Pure over the
/// monotonic clock so the cadence is unit-testable without sleeping.
fn due(last_fired: Option<Instant>, interval: Duration, now: Instant) -> bool {
    match last_fired {
        None => true,
        Some(t) => now.duration_since(t) >= interval,
    }
}

/// Run the resident seller daemon. Never returns on its own — Ctrl-C stops it,
/// and the lock plus write-ahead ledger make that safe.
pub fn run(
    wallet: &Wallet,
    ledger_path: &Path,
    bind: &str,
    eps: Vec<String>,
) -> Result<(), Box<dyn Error>> {
    // Single writer for this wallet's whole run: the File *is* the lock, held
    // for the process lifetime (this function never returns until the process
    // exits, so `_lock` lives as long as the daemon).
    let _lock = storage::lock_dir(&storage::wallet_dir(wallet)?)?;

    // Unlock once: open the signed ledger and bind the socket a single time.
    let mut led = Ledger::open_with_identity(ledger_path, wallet.signing_keypair()?)?;
    let sock = UdpSocket::bind(bind)?;
    sock.set_read_timeout(Some(READ_TIMEOUT))?;

    eprintln!("cm serve: listening on {bind}");
    eprintln!("  ledger:  {}", ledger_path.display());
    eprintln!("  balance: {} sats final", led.balance());
    eprintln!(
        "  card key: {}  (share this — buyers pay you here)",
        discover::card_pubkey_hex(&*wallet.wg_secret_bytes()?)
    );
    if eps.is_empty() {
        eprintln!("  endpoints: none — dial-out only (the card key above still resolves)");
    } else {
        eprintln!("  endpoints: {}", eps.join(", "));
        eprintln!(
            "  direct link: {}@{}  (a peer holding this link dials you without the DHT)",
            wallet.id_hex()?,
            eps[0]
        );
    }

    let mut last_publish: Option<Instant> = None;
    let mut last_watch: Option<Instant> = None;
    loop {
        let now = Instant::now();
        if due(last_publish, REPUBLISH_INTERVAL, now) {
            if let Err(e) = republish(wallet, &eps) {
                eprintln!("[serve] WARN republish: {e}");
            }
            last_publish = Some(now);
        }
        if due(last_watch, WATCH_INTERVAL, now) {
            chain_watch(&mut led, wallet, ledger_path);
            last_watch = Some(now);
        }

        // Drain every buyer waiting on the socket before returning to the
        // timers. A single accept per loop would let one stale datagram, or a
        // buyer who dialed during the (blocking) chain scan, cost a whole watch
        // cycle before being served; accepting until the socket is quiet
        // (Ok(None) = a full read-timeout slice with nothing) keeps handshake
        // latency bounded no matter how long a scan just took.
        loop {
            match FramedTunnel::accept_any(wallet, &sock) {
                Ok(Some((mut tunnel, peer_hex))) => {
                    eprintln!("[serve] session opened with {peer_hex}");
                    let mut rx = Receiver::new(wallet, led.next_address_index());
                    match net::run_receiver(&mut tunnel, &mut rx, &mut led) {
                        Ok(()) => eprintln!(
                            "[serve] session with {peer_hex} closed; balance {} sats final",
                            led.balance()
                        ),
                        Err(e) => eprintln!("[serve] WARN session with {peer_hex} ended: {e}"),
                    }
                    // The accepted tunnel holds a try_clone of this socket and
                    // raised the read timeout to the session length. try_clone
                    // shares the underlying SO_RCVTIMEO, so that long timeout is
                    // now on our listening socket too; restore the short slice
                    // or the next accept would block a full session length and
                    // starve later buyers.
                    sock.set_read_timeout(Some(READ_TIMEOUT))?;
                }
                Ok(None) => break, // socket quiet — go tick the timers
                Err(e) => {
                    eprintln!("[serve] WARN accept failed: {e}");
                    break;
                }
            }
        }
    }
}

/// REPUBLISH duty: sign and put our card so buyers can resolve us. A DHT
/// failure is a WARN — we keep serving. With no endpoints we still publish
/// `{wg, at}`, so the card key resolves even though nobody can dial in.
fn republish(wallet: &Wallet, eps: &[String]) -> Result<(), Box<dyn Error>> {
    let card = Card { wg: wallet.id_hex()?, ep: eps.to_vec(), sp: Some(wallet.sp_code()?), at: ledger::now_unix() };
    let card_key = discover::card_pubkey_hex(&*wallet.wg_secret_bytes()?);
    match discover::publish(&*wallet.wg_secret_bytes()?, &card) {
        Ok(()) if eps.is_empty() => {
            eprintln!("[serve] published card {card_key} (no endpoint — key resolves, dial-out only)")
        }
        Ok(()) => eprintln!("[serve] published card {card_key} @ {}", eps.join(", ")),
        Err(e) => eprintln!("[serve] WARN DHT publish failed ({e}); still serving"),
    }
    Ok(())
}

/// WATCH duty: advance pending payments through the existing reconcile path,
/// then poll the chain for deposits to every still-unpaid issued address and
/// book any we have not already recorded. esplora errors are a WARN and retried
/// next tick — the loop must never die on a transient network fault.
fn chain_watch(led: &mut Ledger, wallet: &Wallet, ledger_path: &Path) {
    match ledger::reconcile(led) {
        Ok(n) if n > 0 => {
            eprintln!("[serve] reconcile: {n} status update(s), balance {} sats final", led.balance())
        }
        Ok(_) => {}
        Err(e) => eprintln!("[serve] WARN reconcile: {e}"),
    }
    for idx in led.issued_unpaid() {
        let addr = match wallet.address(idx) {
            Ok(a) => a.to_string(),
            Err(e) => {
                eprintln!("[serve] WARN address(index {idx}): {e}");
                continue;
            }
        };
        match chain::deposits_to(&addr) {
            Ok(deposits) => {
                for d in deposits {
                    // record_received re-checks has_txid, so a deposit already
                    // logged by a Notify (or a prior tick) is a no-op.
                    match led.record_received(&d.txid, d.sats, idx) {
                        Ok(true) => eprintln!(
                            "[serve] received {} sat @ index {} txid {} ({} confs)",
                            d.sats, idx, d.txid, d.confirmations
                        ),
                        Ok(false) => {}
                        Err(e) => eprintln!("[serve] WARN recording {}: {e}", d.txid),
                    }
                }
            }
            Err(e) => eprintln!("[serve] WARN deposits_to(index {idx}): {e}"),
        }
    }
    // Silent-payment income has no address to poll for — the payer derived a
    // one-time output from our published sp code. Scan the chain for it so a
    // live seller books SP income too. Use a FRESH ledger for the scan (not this
    // loop's long-lived `led`): another writer in the same process (a
    // `cm_collections` call) may have booked income since we opened `led`, and a
    // stale in-memory view would re-book duplicates. `scan_to_tip` also takes the
    // process scan lock, so the two scans never interleave. Best-effort: any
    // error is a WARN.
    match scan_fresh(ledger_path, wallet) {
        Ok((r, sp_balance)) if !r.found.is_empty() => {
            for f in &r.found {
                eprintln!("[serve] silent payment: {} sat at {}:{}", f.sats, f.txid, f.vout);
            }
            eprintln!(
                "[serve] scan: {} new, {} sats silent-payment income",
                r.found.len(),
                sp_balance
            );
        }
        Ok(_) => {}
        Err(e) => eprintln!("[serve] WARN silent-payment scan: {e}"),
    }
}

/// Scan for silent-payment income against a freshly opened ledger, returning the
/// pass report and the resulting SP balance. Opening fresh means the scan's
/// dedup sees every append made by other writers on this file.
fn scan_fresh(
    ledger_path: &Path,
    wallet: &Wallet,
) -> Result<(crate::scan::ScanReport, u64), Box<dyn Error>> {
    let mut led = Ledger::open_with_identity(ledger_path, wallet.signing_keypair()?)?;
    let report = crate::scan::scan_to_tip(wallet, &mut led)?;
    Ok((report, led.sp_balance()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duty_fires_at_start_then_every_interval() {
        let base = Instant::now();
        let iv = Duration::from_secs(60);
        // An unfired duty fires immediately (the "at start" case).
        assert!(due(None, iv, base));
        // Just fired: not due again until a full interval has elapsed.
        assert!(!due(Some(base), iv, base));
        assert!(!due(Some(base), iv, base + Duration::from_secs(59)));
        // Due at exactly the interval, and past it.
        assert!(due(Some(base), iv, base + iv));
        assert!(due(Some(base), iv, base + Duration::from_secs(120)));
    }

    #[test]
    fn republish_and_watch_cadence_are_independent() {
        // The two duties track separate last-fired stamps, so a 60s watch tick
        // does not reset the 45-min republish clock.
        let base = Instant::now();
        let after_watch = base + WATCH_INTERVAL;
        assert!(due(Some(base), WATCH_INTERVAL, after_watch), "watch is due after 60s");
        assert!(
            !due(Some(base), REPUBLISH_INTERVAL, after_watch),
            "republish is NOT due merely because watch fired"
        );
    }
}
