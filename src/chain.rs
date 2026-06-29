//! chain — read/write Bitcoin via bdk + esplora.
//!
//! This is where bdk lives (not in `wallet/`). The wallet hands over
//! descriptor strings; chain syncs the UTXO set and computes balance.
//! The network and esplora endpoint come from `storage` (`CM_NETWORK` /
//! `CM_ESPLORA`); the default is Bitcoin mainnet.

use std::str::FromStr;

use bdk_esplora::esplora_client;
use bdk_esplora::EsploraExt;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, Txid};
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

/// Sync, build a P2TR payment to `to_addr` for `sats`, sign it, and
/// broadcast. Returns the txid. bdk handles coin selection (branch-and-
/// bound) and change. If `max_fee_sats` is set and the built transaction's
/// fee exceeds it, this aborts BEFORE broadcasting — the policy fee cap is
/// enforced at the last moment the fee is known and money has not yet
/// moved. This is the first code path that actually moves money.
pub fn send(
    ext_desc: &str,
    int_desc: &str,
    to_addr: &str,
    sats: u64,
    max_fee_sats: Option<u64>,
) -> Result<Txid, Box<dyn std::error::Error>> {
    // Mainnet fail-closed guard. This is the single chokepoint every send
    // path flows through (cm send, cm pay, cm demo, cm mcp), so the predicate
    // lives in exactly one place. Refuse a mainnet broadcast under an uncapped
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

    // Fee cap: check before signing/broadcasting, so an over-budget fee
    // never leaves the building.
    if let Some(cap) = max_fee_sats {
        let fee = psbt.fee()?.to_sat();
        if fee > cap {
            return Err(format!("fee {fee} sats exceeds policy cap {cap} sats; not broadcasting").into());
        }
    }

    let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
    if !finalized {
        return Err("psbt did not fully sign".into());
    }

    let tx = psbt.extract_tx()?;
    client.broadcast(&tx)?;
    Ok(tx.compute_txid())
}

/// The recommended feerate (sat/vB) for the active network, from esplora's
/// fee estimates. Picks a ~1-hour target (6 blocks), falling back to faster
/// targets, then to a conservative constant if estimates are unavailable —
/// so a mainnet broadcast is never sent at a feerate that won't confirm.
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
    let sat_per_vb = sat_per_vb.ceil().max(1.0) as u64;
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
}
