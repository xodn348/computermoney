//! chain — read/write Bitcoin via bdk + esplora.
//!
//! This is where bdk lives (not in `wallet/`). The wallet hands over
//! descriptor strings; chain syncs the UTXO set and computes balance.
//! The network and esplora endpoint come from `storage` (`CM_NETWORK` /
//! `CM_ESPLORA`); the default is Bitcoin mainnet.

use std::str::FromStr;

use bdk_esplora::esplora_client;
use bdk_esplora::EsploraExt;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, Transaction, Txid};
use bdk_wallet::{SignOptions, Wallet};

use crate::storage;

/// Confirmed + pending balance in satoshis.
pub struct Balance {
    pub confirmed: u64,
    pub pending: u64,
}

/// Build an in-memory bdk wallet from the agent's descriptors.
fn build_wallet(ext_desc: &str, int_desc: &str) -> Result<Wallet, Box<dyn std::error::Error>> {
    let wallet = Wallet::create(ext_desc.to_string(), int_desc.to_string())
        .network(storage::network())
        .create_wallet_no_persist()?;
    Ok(wallet)
}

/// Sync the descriptor's UTXOs from esplora and return the balance.
pub fn balance(ext_desc: &str, int_desc: &str) -> Result<Balance, Box<dyn std::error::Error>> {
    let mut wallet = build_wallet(ext_desc, int_desc)?;

    let client = esplora_client::Builder::new(&storage::esplora_endpoint()).build_blocking();
    let request = wallet.start_full_scan().build();
    let update = client.full_scan(request, 5, 1)?;
    wallet.apply_update(update)?;

    let b = wallet.balance();
    Ok(Balance {
        confirmed: b.confirmed.to_sat(),
        pending: (b.trusted_pending + b.untrusted_pending).to_sat(),
    })
}

/// Sync, build a P2TR payment to `to_addr` for `sats`, and sign it — but do
/// NOT broadcast. Returns the signed transaction and its fee in sats. bdk
/// handles coin selection (branch-and-bound) and change. If `max_fee_sats` is
/// set and the built transaction's fee exceeds it, this aborts — the policy
/// fee cap is enforced at the last moment the fee is known. Splitting the
/// broadcast out (see [`broadcast`]) lets a caller record the payment in the
/// ledger BEFORE the money moves, closing the crash-between-broadcast-and-
/// record gap (Finding C).
pub fn build_signed(
    ext_desc: &str,
    int_desc: &str,
    to_addr: &str,
    sats: u64,
    max_fee_sats: Option<u64>,
) -> Result<(Transaction, u64), Box<dyn std::error::Error>> {
    // Mainnet fail-closed guard. This is the single chokepoint every send
    // path flows through (cm send, cm pay, cm demo, cm mcp), so the predicate
    // lives in exactly one place. Refuse a mainnet build under an uncapped
    // policy before any network, signing, or coin selection happens.
    crate::policy::ensure_mainnet_capped(storage::network(), &crate::policy::Policy::load()?)?;

    let mut wallet = build_wallet(ext_desc, int_desc)?;

    let client = esplora_client::Builder::new(&storage::esplora_endpoint()).build_blocking();
    let request = wallet.start_full_scan().build();
    let update = client.full_scan(request, 5, 1)?;
    wallet.apply_update(update)?;

    let recipient = Address::from_str(to_addr)?.require_network(storage::network())?;

    // Use the network's recommended feerate so the tx actually confirms.
    // (No RBF/CPFP fee-bumping yet — a tx stuck behind a fee spike is the
    // known gap on mainnet; this feerate is the floor that avoids underpaying.)
    let feerate = recommended_feerate(&client)?;
    let mut builder = wallet.build_tx();
    builder.fee_rate(feerate);
    builder.add_recipient(recipient.script_pubkey(), Amount::from_sat(sats));
    let mut psbt = builder.finish()?;

    // Fee cap: check before signing, so an over-budget fee never leaves the
    // building. The fee is returned so the caller need not recompute it.
    let fee = psbt.fee()?.to_sat();
    if let Some(cap) = max_fee_sats {
        if fee > cap {
            return Err(format!("fee {fee} sats exceeds policy cap {cap} sats; not broadcasting").into());
        }
    }

    let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
    if !finalized {
        return Err("psbt did not fully sign".into());
    }

    let tx = psbt.extract_tx()?;
    Ok((tx, fee))
}

/// Broadcast an already-signed transaction and return its txid. The only
/// step that actually moves money — kept separate from [`build_signed`] so
/// the ledger write can be ordered ahead of it.
pub fn broadcast(tx: &Transaction) -> Result<Txid, Box<dyn std::error::Error>> {
    let client = esplora_client::Builder::new(&storage::esplora_endpoint()).build_blocking();
    client.broadcast(tx)?;
    Ok(tx.compute_txid())
}

/// A payment observed landing on one of our addresses. `sats` is the sum of
/// this tx's outputs paying that exact address (a tx may pay it in several
/// outputs, and also pay change/others which must not count); `confirmations`
/// mirrors [`confirmations`] — 0 if unconfirmed, else tip - height + 1.
pub struct Deposit {
    pub txid: String,
    pub sats: u64,
    pub confirmations: u32,
}

/// Every deposit paying `addr`, newest first. The seller daemon polls this to
/// notice money arriving with NO listener — there is no notification, the chain
/// is the only proof of receipt. A stateless read: no wallet, no descriptors,
/// just the address's on-chain history from esplora.
pub fn deposits_to(addr: &str) -> Result<Vec<Deposit>, Box<dyn std::error::Error>> {
    let address = Address::from_str(addr)?.require_network(storage::network())?;
    let spk = address.script_pubkey();

    let client = esplora_client::Builder::new(&storage::esplora_endpoint()).build_blocking();
    let txs = client.get_address_txs(&address, None)?;
    let tip = client.get_height()?;

    let mut out = Vec::new();
    for tx in txs {
        // Count only the outputs paying this address; a tx that merely spends
        // through us (change to another of our keys, payments to third parties)
        // must not be booked as a deposit to this address.
        let sats: u64 = tx.vout.iter().filter(|v| v.scriptpubkey == spk).map(|v| v.value).sum();
        if sats == 0 {
            continue;
        }
        let confirmations = if !tx.status.confirmed {
            0
        } else {
            match tx.status.block_height {
                Some(h) => tip.saturating_sub(h) + 1,
                None => 0,
            }
        };
        out.push(Deposit { txid: tx.txid.to_string(), sats, confirmations });
    }
    Ok(out)
}

/// The outcome of trying to (re)broadcast a stored signed tx during reconcile.
pub enum Rebroadcast {
    /// Accepted by the network, or already known to it — the tx is alive and
    /// should stay Pending.
    Accepted,
    /// Hard rejection: the tx's inputs are gone or it conflicts with a
    /// confirmed spend, so it can never confirm. reconcile marks it Failed.
    Rejected(String),
}

/// Rebroadcast a sidecar tx (raw consensus hex). A crash may have left a
/// Pending Sent whose broadcast never happened, or whose tx was later
/// evicted; reconcile calls this to push it back to the network. Classifies
/// the result conservatively: any success or benign "already known" error is
/// [`Rebroadcast::Accepted`] (stay Pending); only a provably-dead tx (inputs
/// missing/spent, mempool conflict) is [`Rebroadcast::Rejected`].
pub fn rebroadcast_hex(hex: &str) -> Result<Rebroadcast, Box<dyn std::error::Error>> {
    let tx: Transaction = bdk_wallet::bitcoin::consensus::encode::deserialize_hex(hex)?;
    match broadcast(&tx) {
        Ok(_) => Ok(Rebroadcast::Accepted),
        Err(e) => {
            let msg = e.to_string();
            if is_hard_rejection(&msg) {
                Ok(Rebroadcast::Rejected(msg))
            } else {
                Ok(Rebroadcast::Accepted)
            }
        }
    }
}

/// Whether a broadcast error string means the tx can NEVER confirm (its
/// inputs are missing/spent, or it conflicts with a confirmed spend) — as
/// opposed to a transient or benign "already known" error. Kept pure and
/// string-based so it is unit-testable without a network.
fn is_hard_rejection(msg: &str) -> bool {
    let m = msg.to_lowercase();
    m.contains("missingorspent")
        || m.contains("bad-txns-inputs")
        || m.contains("missing inputs")
        || m.contains("missing-inputs")
        || m.contains("txn-mempool-conflict")
        || m.contains("conflict")
}

/// Upper bound on the feerate we will ever set (sat/vB). A runaway esplora
/// estimate must not translate into an absurd fee, so the chosen feerate is
/// clamped into `[1, MAX_FEERATE_SAT_PER_VB]`. 200 sat/vB is already an
/// extreme mainnet feerate — well above any healthy confirmation target.
const MAX_FEERATE_SAT_PER_VB: u64 = 200;

/// Clamp a feerate estimate into the sane `[1, MAX_FEERATE_SAT_PER_VB]`
/// range. Pure, so the clamp is testable without a network.
fn clamp_feerate(sat_per_vb: u64) -> u64 {
    sat_per_vb.clamp(1, MAX_FEERATE_SAT_PER_VB)
}

/// The recommended feerate (sat/vB) for the active network, from esplora's
/// fee estimates. Picks a ~1-hour target (6 blocks), falling back to faster
/// targets, then to a conservative constant if estimates are unavailable —
/// so a mainnet broadcast is never sent at a feerate that won't confirm. The
/// result is clamped to `[1, MAX_FEERATE_SAT_PER_VB]`: a floor that avoids
/// underpaying and a ceiling that caps a runaway estimate.
fn recommended_feerate(
    client: &esplora_client::BlockingClient,
) -> Result<FeeRate, Box<dyn std::error::Error>> {
    let fallback = if storage::network() == Network::Bitcoin { 6.0 } else { 1.0 };
    let est = client.get_fee_estimates().unwrap_or_default();
    let sat_per_vb = est
        .get(&6)
        .or_else(|| est.get(&3))
        .or_else(|| est.get(&2))
        .or_else(|| est.get(&1))
        .copied()
        .unwrap_or(fallback);
    // `ceil() as u64` saturates (huge -> u64::MAX, negative -> 0); the clamp
    // then brings both extremes back into range.
    let sat_per_vb = clamp_feerate(sat_per_vb.ceil() as u64);
    FeeRate::from_sat_per_vb(sat_per_vb).ok_or_else(|| "invalid feerate".into())
}

/// Confirmation count for a txid: 0 if unconfirmed/unknown, else
/// tip_height - block_height + 1. Used by reconcile to advance ledger
/// status. A stateless read — no wallet needed.
pub fn confirmations(txid_str: &str) -> Result<u32, Box<dyn std::error::Error>> {
    let client = esplora_client::Builder::new(&storage::esplora_endpoint()).build_blocking();
    let txid = Txid::from_str(txid_str)?;
    let status = client.get_tx_status(&txid)?;
    if !status.confirmed {
        return Ok(0);
    }
    let tip = client.get_height()?;
    match status.block_height {
        Some(h) => Ok(tip.saturating_sub(h) + 1),
        None => Ok(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet as CmWallet;
    use bdk_wallet::KeychainKind;

    const VECTOR_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // The load-bearing consistency check: bdk's descriptor-based derivation
    // and wallet.rs's manual BIP-86 derivation MUST produce the same
    // address, or `chain/` and `wallet/` would disagree about where money
    // lands. No network needed.
    #[test]
    fn bdk_descriptor_matches_manual_derivation() {
        let cm = CmWallet::from_mnemonic(VECTOR_MNEMONIC).unwrap();
        let (ext, int) = cm.descriptors();
        let bdk = build_wallet(&ext, &int).unwrap();
        for i in 0..3 {
            let bdk_addr = bdk.peek_address(KeychainKind::External, i).address.to_string();
            let manual = cm.address(i).unwrap().to_string();
            assert_eq!(bdk_addr, manual, "mismatch at index {i}");
        }
    }

    #[test]
    fn feerate_clamp_bounds_the_estimate() {
        assert_eq!(clamp_feerate(0), 1, "floor: never below 1 sat/vB");
        assert_eq!(clamp_feerate(1), 1);
        assert_eq!(clamp_feerate(50), 50, "in-range value passes through");
        assert_eq!(clamp_feerate(MAX_FEERATE_SAT_PER_VB), MAX_FEERATE_SAT_PER_VB);
        assert_eq!(clamp_feerate(10_000), MAX_FEERATE_SAT_PER_VB, "ceiling caps a runaway estimate");
        assert_eq!(clamp_feerate(u64::MAX), MAX_FEERATE_SAT_PER_VB);
    }

    #[test]
    fn hard_rejection_only_for_provably_dead_txs() {
        // Inputs gone / conflicting spend => never confirms.
        assert!(is_hard_rejection("sendrawtransaction RPC error: bad-txns-inputs-missingorspent"));
        assert!(is_hard_rejection("txn-mempool-conflict"));
        // Benign / transient => stay Pending, do not un-debit.
        assert!(!is_hard_rejection("txn-already-known"));
        assert!(!is_hard_rejection("Transaction already in block chain"));
        assert!(!is_hard_rejection("min relay fee not met"));
        assert!(!is_hard_rejection("HTTP 500 Internal Server Error"));
    }
}
