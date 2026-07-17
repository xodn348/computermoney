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

use bitcoin::secp256k1::SecretKey;

use crate::chain;
use crate::ledger::{self, Entry, Ledger, Status};
use crate::wallet::Wallet;

/// Smallest silent-payment send. Receiver scanners (ours included) drop
/// sub-floor outputs as dust, so anything below this would arrive unseen.
pub const SP_MIN_SATS: u64 = 330;

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

/// Pay a Silent Payments code (`sp1…`/`tsp1…`): derive a one-time address from
/// our descriptor inputs and send to it, with the same build → record →
/// broadcast ordering as [`send`]. The recipient's code is decoded here so a
/// network mismatch fails before any money moves; `Sent.to` stores the code so
/// the ledger documents intent (the on-chain address is one-time and opaque).
///
/// The caller has already gated the *payee handle* (the sp code) against the
/// blocklist. A silent payment's on-chain destination is a one-time address that
/// cannot be pre-listed, so as a uniform belt-and-suspenders control we also run
/// the address check on the derived address here — it catches the rare case
/// where the derived output happens to match a blocklisted address.
pub fn sp_send(
    led: &mut Ledger,
    wallet: &Wallet,
    ext: &str,
    int: &str,
    code: &str,
    sats: u64,
    max_fee_sats: Option<u64>,
) -> Result<String, Box<dyn Error>> {
    if sats < SP_MIN_SATS {
        return Err(format!(
            "silent-payment sends need at least {SP_MIN_SATS} sats \
             (receiver scanners ignore dust below that floor); got {sats}"
        )
        .into());
    }
    let (scan, spend, net) = crate::sp::decode(code)?;
    if net != crate::storage::network() {
        return Err(format!(
            "silent-payment code is for {net:?}, wallet is on {:?}",
            crate::storage::network()
        )
        .into());
    }

    // Received SP income funds this send too, so an agent spends what it earned
    // to pay an sp code or a 402 endpoint, not only via a plain-address send.
    let sp_utxos = led.sp_utxos();
    let spend_sk = SecretKey::from_keypair(&wallet.sp_spend_keypair()?);
    let (tx, _fee, address, consumed) =
        chain::build_signed_to_sp(ext, int, &scan, &spend, sats, max_fee_sats, &sp_utxos, &spend_sk)?;
    crate::policy::Policy::load()?.check_address(&address.to_string())?;
    let txid = tx.compute_txid().to_string();

    let tx_hex = bdk_wallet::bitcoin::consensus::encode::serialize_hex(&tx);
    led.write_sidecar(&txid, &tx_hex)?;
    led.append(Entry::Sent {
        seq: led.next_seq(),
        txid: txid.clone(),
        sats,
        to: code.to_string(),
        status: Status::Pending,
        at: ledger::now_unix(),
    })?;

    chain::broadcast(&tx)?;

    for op in consumed {
        led.record_sp_spent(&op.txid.to_string(), op.vout)?;
    }
    Ok(txid)
}

/// Send to a normal address, drawing on received Silent Payments outputs as
/// well as descriptor UTXOs — the path that makes SP income spendable. Same
/// build → record → broadcast ordering as [`send`]; additionally books an
/// `SpSpent` for each consumed SP outpoint AFTER the broadcast (the scanner
/// also observes the spend on-chain, and `SpSpent` is idempotent, so a crash
/// in the gap self-heals). With no SP funds this behaves exactly like [`send`].
pub fn send_spending_sp(
    led: &mut Ledger,
    wallet: &Wallet,
    ext: &str,
    int: &str,
    to: &str,
    sats: u64,
    max_fee_sats: Option<u64>,
) -> Result<String, Box<dyn Error>> {
    let sp_utxos = led.sp_utxos();
    let spend_sk = SecretKey::from_keypair(&wallet.sp_spend_keypair()?);

    let (tx, _fee, consumed) =
        chain::build_signed_spending_sp(ext, int, to, sats, max_fee_sats, &sp_utxos, &spend_sk)?;
    let txid = tx.compute_txid().to_string();

    let tx_hex = bdk_wallet::bitcoin::consensus::encode::serialize_hex(&tx);
    led.write_sidecar(&txid, &tx_hex)?;
    led.append(Entry::Sent {
        seq: led.next_seq(),
        txid: txid.clone(),
        sats,
        to: to.to_string(),
        status: Status::Pending,
        at: ledger::now_unix(),
    })?;

    chain::broadcast(&tx)?;

    for op in consumed {
        led.record_sp_spent(&op.txid.to_string(), op.vout)?;
    }
    Ok(txid)
}
