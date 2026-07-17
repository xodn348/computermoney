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
use bdk_wallet::{KeychainKind, SignOptions, Wallet};

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, TweakedPublicKey};
use bitcoin::secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{OutPoint, ScriptBuf, TxOut, Weight};

use crate::ledger::SpUtxo;
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

/// Sync, then build+sign a Silent Payments send to the receiver identified by
/// `(scan, spend)` — but do NOT broadcast. Unlike [`build_signed`], the inputs
/// must be pinned BEFORE the recipient address exists: a BIP-352 one-time
/// address is derived from the exact set of inputs that fund it. So this does
/// its own largest-first selection over the descriptor UTXOs, derives each
/// input's Taproot output-key secret, computes the one-time P2TR address, and
/// only then runs the builder with `manually_selected_only` over that pinned
/// set. Change still returns to the internal descriptor. The fee cap is
/// enforced exactly as in [`build_signed`].
pub fn build_signed_to_sp(
    ext_desc: &str,
    int_desc: &str,
    scan: &PublicKey,
    spend: &PublicKey,
    sats: u64,
    max_fee_sats: Option<u64>,
    sp_utxos: &[SpUtxo],
    sp_spend_sk: &SecretKey,
) -> Result<(Transaction, u64, Address, Vec<OutPoint>), Box<dyn std::error::Error>> {
    crate::policy::ensure_mainnet_capped(storage::network(), &crate::policy::Policy::load()?)?;

    let mut wallet = build_wallet(ext_desc, int_desc)?;
    let client = esplora_client::Builder::new(&storage::esplora_endpoint()).build_blocking();
    let request = wallet.start_full_scan().build();
    let update = client.full_scan(request, 5, 1)?;
    wallet.apply_update(update)?;

    let feerate = recommended_feerate(&client)?;
    let fr = feerate.to_sat_per_vb_ceil();
    let secp = Secp256k1::new();

    // Received SP outputs are mandatory inputs (consolidating, like the
    // plain-address spend path), so income earned via silent payments funds a
    // send to an sp code / HTTP-402 endpoint — not only a plain-address send.
    // Each contributes its `b_spend + tweak` (even-Y normalized) to the BIP-352
    // input-key sum that fixes the recipient's one-time address.
    let mut sp_inputs: Vec<crate::sp::SpInput> = Vec::new();
    let mut sp_by_outpoint: Vec<(OutPoint, [u8; 32])> = Vec::with_capacity(sp_utxos.len());
    let mut sp_total = 0u64;
    for u in sp_utxos {
        let outpoint = OutPoint::new(Txid::from_str(&u.txid)?, u.vout);
        let tweak = decode_hex32(&u.tweak)?;
        let out_sk = SecretKey::from_keypair(&crate::sp::spend_keypair(sp_spend_sk, &tweak)?);
        sp_inputs.push(crate::sp::SpInput { outpoint, key: crate::sp::taproot_input_key(out_sk) });
        sp_by_outpoint.push((outpoint, tweak));
        sp_total += u.sats;
    }

    // Add descriptor UTXOs largest-first for whatever the SP inputs (worth
    // `sp_total`) don't already cover — often nothing. The SP input count feeds
    // the fee estimate so change stays solvent.
    let desc_utxos: Vec<(OutPoint, u64, KeychainKind, u32)> = wallet
        .list_unspent()
        .map(|o| (o.outpoint, o.txout.value.to_sat(), o.keychain, o.derivation_index))
        .collect();
    let selected_desc = select_largest_first(desc_utxos, sats, fr, sp_total, sp_utxos.len() as u64)
        .ok_or_else(|| {
            format!(
                "insufficient funds for silent payment: need {sats} sats + fee \
                 (ordinary + silent-payment income together)"
            )
        })?;

    // Descriptor input keys (BIP-86 leaf tweaked to the output key, even-Y
    // normalized) join the sum, then the one-time address is fixed over every
    // input.
    let master = master_xprv_from_descriptor(ext_desc)?;
    let coin = coin_type();
    for (op, _v, kc, idx) in &selected_desc {
        let key = taproot_input_secret(&secp, &master, coin, keychain_branch(*kc), *idx)?;
        sp_inputs.push(crate::sp::SpInput { outpoint: *op, key });
    }
    let recipient = crate::sp::send_address(&sp_inputs, scan, spend, storage::network())?;

    let mut builder = wallet.build_tx();
    builder.manually_selected_only();
    builder.fee_rate(feerate);
    for (op, _v, _kc, _idx) in &selected_desc {
        builder.add_utxo(*op)?;
    }
    for u in sp_utxos {
        let outpoint = OutPoint::new(Txid::from_str(&u.txid)?, u.vout);
        let tweak = decode_hex32(&u.tweak)?;
        let kp = crate::sp::spend_keypair(sp_spend_sk, &tweak)?;
        let (xonly, _parity) = kp.x_only_public_key();
        let spk = ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(xonly));
        let mut pin = bitcoin::psbt::Input::default();
        pin.witness_utxo = Some(TxOut { value: Amount::from_sat(u.sats), script_pubkey: spk });
        builder.add_foreign_utxo(outpoint, pin, Weight::from_wu(66))?;
    }
    builder.add_recipient(recipient.script_pubkey(), Amount::from_sat(sats));
    let mut psbt = builder.finish()?;

    let fee = psbt.fee()?.to_sat();
    if let Some(cap) = max_fee_sats {
        if fee > cap {
            return Err(format!("fee {fee} sats exceeds policy cap {cap} sats; not broadcasting").into());
        }
    }

    // Descriptor inputs signed by bdk, SP inputs key-path signed by hand — the
    // same mixed finalize the plain-address spend path uses. trust_witness_utxo:
    // the SP inputs are foreign and carry only witness_utxo.
    let sign_opts = SignOptions {
        try_finalize: false,
        trust_witness_utxo: true,
        ..SignOptions::default()
    };
    wallet.sign(&mut psbt, sign_opts)?;
    finalize_mixed_psbt(&mut psbt, &sp_by_outpoint, sp_spend_sk, &secp)?;

    let tx = psbt.extract_tx()?;
    let consumed = sp_by_outpoint.iter().map(|(op, _)| *op).collect();
    Ok((tx, fee, recipient, consumed))
}

/// Sync, then build+sign a normal payment to `to_addr` that may draw on
/// received Silent Payments outputs in addition to descriptor UTXOs — but do
/// NOT broadcast. Each `SpUtxo` is added as a foreign input (bdk cannot derive
/// its key from a descriptor); bdk still selects any additional descriptor
/// UTXOs, sets the fee, and makes change. Descriptor inputs are signed by bdk;
/// the SP inputs are then key-path signed manually with `b_spend + tweak`.
/// Returns the tx, its fee, and the SP outpoints it consumes (for `SpSpent`).
/// With no SP UTXOs this is exactly [`build_signed`].
pub fn build_signed_spending_sp(
    ext_desc: &str,
    int_desc: &str,
    to_addr: &str,
    sats: u64,
    max_fee_sats: Option<u64>,
    sp_utxos: &[SpUtxo],
    sp_spend_sk: &SecretKey,
) -> Result<(Transaction, u64, Vec<OutPoint>), Box<dyn std::error::Error>> {
    if sp_utxos.is_empty() {
        let (tx, fee) = build_signed(ext_desc, int_desc, to_addr, sats, max_fee_sats)?;
        return Ok((tx, fee, Vec::new()));
    }

    crate::policy::ensure_mainnet_capped(storage::network(), &crate::policy::Policy::load()?)?;

    let mut wallet = build_wallet(ext_desc, int_desc)?;
    let client = esplora_client::Builder::new(&storage::esplora_endpoint()).build_blocking();
    let request = wallet.start_full_scan().build();
    let update = client.full_scan(request, 5, 1)?;
    wallet.apply_update(update)?;

    let recipient = Address::from_str(to_addr)?.require_network(storage::network())?;
    let feerate = recommended_feerate(&client)?;

    let secp = Secp256k1::new();
    let mut builder = wallet.build_tx();
    builder.fee_rate(feerate);
    builder.add_recipient(recipient.script_pubkey(), Amount::from_sat(sats));

    // Every SP output becomes a mandatory (foreign) input, so received funds are
    // spendable through the same builder as descriptor funds. Its key is
    // `b_spend + tweak`; its scriptPubKey is P2TR of that key used verbatim.
    let mut sp_by_outpoint: Vec<(OutPoint, [u8; 32])> = Vec::with_capacity(sp_utxos.len());
    for u in sp_utxos {
        let outpoint = OutPoint::new(Txid::from_str(&u.txid)?, u.vout);
        let tweak = decode_hex32(&u.tweak)?;
        let kp = crate::sp::spend_keypair(sp_spend_sk, &tweak)?;
        let (xonly, _parity) = kp.x_only_public_key();
        let spk = ScriptBuf::new_p2tr_tweaked(TweakedPublicKey::dangerous_assume_tweaked(xonly));
        let mut pin = bitcoin::psbt::Input::default();
        pin.witness_utxo = Some(TxOut { value: Amount::from_sat(u.sats), script_pubkey: spk });
        // Taproot key-path witness: one 64-byte signature => 66 WU.
        builder.add_foreign_utxo(outpoint, pin, Weight::from_wu(66))?;
        sp_by_outpoint.push((outpoint, tweak));
    }

    let mut psbt = builder.finish()?;

    let fee = psbt.fee()?.to_sat();
    if let Some(cap) = max_fee_sats {
        if fee > cap {
            return Err(format!("fee {fee} sats exceeds policy cap {cap} sats; not broadcasting").into());
        }
    }

    // Sign descriptor inputs (bdk fills tap_key_sig) without finalizing, then
    // finalize every input by hand: descriptor inputs from bdk's signature, SP
    // inputs from a fresh key-path signature under `b_spend + tweak`.
    // trust_witness_utxo: the SP inputs are foreign and carry only witness_utxo;
    // without it bdk's signer demands a non-witness UTXO and refuses to sign.
    let sign_opts = SignOptions {
        try_finalize: false,
        trust_witness_utxo: true,
        ..SignOptions::default()
    };
    wallet.sign(&mut psbt, sign_opts)?;
    finalize_mixed_psbt(&mut psbt, &sp_by_outpoint, sp_spend_sk, &secp)?;

    let tx = psbt.extract_tx()?;
    let consumed = sp_by_outpoint.iter().map(|(op, _)| *op).collect();
    Ok((tx, fee, consumed))
}

/// Finalize a PSBT whose inputs are a mix of bdk-signed descriptor Taproot
/// key-path inputs and manually-signed Silent Payments inputs. All are
/// key-path spends, so each witness is a single Schnorr signature.
fn finalize_mixed_psbt(
    psbt: &mut bitcoin::psbt::Psbt,
    sp_by_outpoint: &[(OutPoint, [u8; 32])],
    sp_spend_sk: &SecretKey,
    secp: &Secp256k1<All>,
) -> Result<(), Box<dyn std::error::Error>> {
    use bitcoin::Witness;

    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().ok_or_else(|| "psbt input missing witness_utxo".to_string()))
        .collect::<Result<_, _>>()?;
    let unsigned = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned);

    for i in 0..unsigned.input.len() {
        let outpoint = unsigned.input[i].previous_output;
        if let Some((_, tweak)) = sp_by_outpoint.iter().find(|(op, _)| *op == outpoint) {
            let sighash = cache.taproot_key_spend_signature_hash(
                i,
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )?;
            let kp = crate::sp::spend_keypair(sp_spend_sk, tweak)?;
            let msg = Message::from_digest(sighash.to_byte_array());
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
            let mut w = Witness::new();
            w.push(sig.as_ref());
            psbt.inputs[i].final_script_witness = Some(w);
        } else {
            let ts = psbt.inputs[i]
                .tap_key_sig
                .ok_or_else(|| format!("descriptor input {i} was not signed"))?;
            let mut w = Witness::new();
            w.push(ts.serialize());
            psbt.inputs[i].final_script_witness = Some(w);
        }
    }
    Ok(())
}

/// Parse the master Xpriv out of a `tr(<xprv>/86h/…)` descriptor. The wallet
/// builds these strings with the bare master key at the front, so the xprv is
/// everything between `tr(` and the first `/`.
fn master_xprv_from_descriptor(desc: &str) -> Result<Xpriv, Box<dyn std::error::Error>> {
    let inner = desc.strip_prefix("tr(").ok_or("descriptor is not a tr() descriptor")?;
    let xprv_str = inner.split('/').next().ok_or("descriptor has no key")?;
    Ok(Xpriv::from_str(xprv_str)?)
}

/// The BIP-86 leaf at `m/86'/{coin}'/0'/{branch}/{index}`, tweaked to its
/// Taproot output key and normalized to even Y — i.e. the discrete log of the
/// output key, which is what BIP-352 sums into the shared secret.
fn taproot_input_secret(
    secp: &Secp256k1<All>,
    master: &Xpriv,
    coin: u32,
    branch: u32,
    index: u32,
) -> Result<SecretKey, Box<dyn std::error::Error>> {
    let path = DerivationPath::from_str(&format!("m/86'/{coin}'/0'/{branch}/{index}"))?;
    let child = master.derive_priv(secp, &path)?;
    let tweaked = child.to_keypair(secp).tap_tweak(secp, None);
    let out_sk = SecretKey::from_keypair(&tweaked.to_keypair());
    Ok(crate::sp::taproot_input_key(out_sk))
}

/// Largest-first descriptor-UTXO selection for a Silent Payments send. Sorts
/// descending by value and accumulates until `prefunded` (value already supplied
/// by pinned SP inputs) plus the running total covers `sats` plus an estimated
/// fee (`fr` sat/vB over a vsize that grows with both the selected and the
/// `pinned_inputs` count). Returns `Some(vec![])` when the pinned inputs alone
/// cover it, or `None` when the wallet cannot. Pure, so it is unit-testable
/// without a chain.
fn select_largest_first(
    mut utxos: Vec<(OutPoint, u64, KeychainKind, u32)>,
    sats: u64,
    fr: u64,
    prefunded: u64,
    pinned_inputs: u64,
) -> Option<Vec<(OutPoint, u64, KeychainKind, u32)>> {
    utxos.sort_by(|a, b| b.1.cmp(&a.1));
    // ~58 vB per Taproot key-path input, plus recipient + change + overhead.
    let target = |n_desc: u64| {
        let est_vsize = 11 + (n_desc + pinned_inputs) * 58 + 43 + 43;
        sats.saturating_add(fr.saturating_mul(est_vsize))
    };
    if prefunded >= target(0) {
        return Some(Vec::new());
    }
    let mut selected: Vec<(OutPoint, u64, KeychainKind, u32)> = Vec::new();
    let mut running = prefunded;
    for u in utxos {
        selected.push(u);
        running += u.1;
        if running >= target(selected.len() as u64) {
            return Some(selected);
        }
    }
    None
}

fn keychain_branch(kind: KeychainKind) -> u32 {
    match kind {
        KeychainKind::External => 0,
        KeychainKind::Internal => 1,
    }
}

fn coin_type() -> u32 {
    if storage::network() == Network::Bitcoin {
        0
    } else {
        1
    }
}

/// Decode 64 lowercase-hex chars into 32 bytes (the ledger stores SP tweaks
/// this way). Keeps a hex crate out of the dependency set.
fn decode_hex32(s: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if s.len() != 64 {
        return Err(format!("tweak must be 64 hex chars, got {}", s.len()).into());
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
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

    // The SP send derives each input key by tweaking the BIP-86 leaf to its
    // Taproot output key. That derived secret must reproduce the SAME output
    // key the descriptor address commits to — otherwise the shared secret (and
    // the money) would be wrong. Network-free: checks key == address's key.
    #[test]
    fn taproot_input_secret_matches_descriptor_address() {
        use bitcoin::key::TweakedPublicKey;
        use bitcoin::{Address, KnownHrp};
        let cm = CmWallet::from_mnemonic_on(Network::Signet, VECTOR_MNEMONIC).unwrap();
        let (ext, _int) = cm.descriptors();
        let master = master_xprv_from_descriptor(&ext).unwrap();
        let secp = Secp256k1::new();
        for i in 0..3u32 {
            // coin type 1 (signet); external branch 0, index i.
            let sk = taproot_input_secret(&secp, &master, 1, 0, i).unwrap();
            let xonly = PublicKey::from_secret_key(&secp, &sk).x_only_public_key().0;
            let from_key = Address::p2tr_tweaked(
                TweakedPublicKey::dangerous_assume_tweaked(xonly),
                KnownHrp::Testnets,
            );
            assert_eq!(from_key, cm.address(i).unwrap(), "input key disagrees with address at {i}");
        }
    }

    #[test]
    fn master_xprv_parses_out_of_descriptor() {
        let cm = CmWallet::from_mnemonic_on(Network::Signet, VECTOR_MNEMONIC).unwrap();
        let (ext, int) = cm.descriptors();
        // Both descriptors carry the same master key at the front.
        assert_eq!(
            master_xprv_from_descriptor(&ext).unwrap(),
            master_xprv_from_descriptor(&int).unwrap()
        );
        assert!(master_xprv_from_descriptor("wpkh(x)").is_err());
    }

    #[test]
    fn largest_first_selects_high_value_and_covers_amount() {
        fn op(n: u8) -> OutPoint {
            let mut b = [0u8; 32];
            b[0] = n;
            OutPoint::new(bitcoin::Txid::from_slice(&b).unwrap(), 0)
        }
        let utxos = vec![
            (op(1), 1_000u64, KeychainKind::External, 0u32),
            (op(2), 50_000, KeychainKind::External, 1),
            (op(3), 3_000, KeychainKind::Internal, 0),
        ];
        // One big UTXO covers 40k + fee: selection takes the 50k first and stops.
        let sel = select_largest_first(utxos.clone(), 40_000, 2, 0, 0).unwrap();
        assert_eq!(sel.len(), 1);
        assert_eq!(sel[0].1, 50_000, "largest first");
        // Amount exceeding the whole wallet cannot be covered.
        assert!(select_largest_first(utxos.clone(), 60_000, 2, 0, 0).is_none());
        // Prefunded (SP) inputs covering the whole amount + fee => no descriptor
        // UTXO needed, so an empty selection is returned (not None).
        assert_eq!(
            select_largest_first(utxos.clone(), 40_000, 2, 60_000, 1).unwrap().len(),
            0
        );
        // A tiny amount still needs enough to clear the fee; multiple small
        // UTXOs accumulate.
        let small = vec![
            (op(4), 800u64, KeychainKind::External, 0u32),
            (op(5), 900, KeychainKind::External, 1),
            (op(6), 1_100, KeychainKind::Internal, 0),
        ];
        let sel = select_largest_first(small, 1_500, 1, 0, 0).unwrap();
        assert!(sel.iter().map(|u| u.1).sum::<u64>() >= 1_500);
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
