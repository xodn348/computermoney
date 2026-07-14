//! pay — the ordering-critical send path, in one place.
//!
//! Finding C: broadcasting before the ledger records the Sent entry means a
//! crash in that gap moves money with no durable record — balance drifts, the
//! daily-limit fold undercounts, and a retry can double-pay. This module
//! inverts the order: build+sign, persist the signed tx as a sidecar and
//! append a durable Pending `Sent` entry, and only THEN broadcast. If the
//! process dies after the ledger write, the Pending entry keeps the payment on
//! the work queue and the sidecar lets reconcile rebroadcast it (or, if it is
//! proven dead, mark it Failed and un-debit).
//!
//! The policy checks (amount, daily, address) stay at the call sites; they
//! gate before we get here. This module owns only the build → record →
//! broadcast ordering, so all three send paths (`cm send`, `cm pay`, the MCP
//! `cm_send`) inherit the same crash-safety from one place.

use std::error::Error;

use crate::chain;
use crate::ledger::{self, Entry, Ledger, Status};

/// Build+sign a payment, record it durably, then broadcast — in that order.
/// Returns the txid string. Callers use the returned txid for their own
/// notify/print/response logic; policy checks are the caller's responsibility
/// and must already have passed.
pub fn send(
    led: &mut Ledger,
    ext: &str,
    int: &str,
    to: &str,
    sats: u64,
    max_fee_sats: Option<u64>,
) -> Result<String, Box<dyn Error>> {
    let (tx, _fee) = chain::build_signed(ext, int, to, sats, max_fee_sats)?;
    let txid = tx.compute_txid().to_string();

    // Persist the signed tx BEFORE broadcasting: if we crash between the
    // ledger write and the broadcast, reconcile finds this sidecar and
    // rebroadcasts it. The hex is the raw consensus encoding.
    let tx_hex = bdk_wallet::bitcoin::consensus::encode::serialize_hex(&tx);
    led.write_sidecar(&txid, &tx_hex)?;

    // Durable Pending record BEFORE the money moves. This is the line that
    // closes Finding C: after it, a crash cannot lose the payment.
    led.append(Entry::Sent {
        seq: led.next_seq(),
        txid: txid.clone(),
        sats,
        to: to.to_string(),
        status: Status::Pending,
        at: ledger::now_unix(),
    })?;

    // Now move the money. A failure here leaves the Pending entry + sidecar,
    // which reconcile turns into either a rebroadcast or a Failed un-debit.
    chain::broadcast(&tx)?;
    Ok(txid)
}
