//! scan — Silent Payments chain scanner.
//!
//! A receiver is paid without being online (see `sp`): the payer derives a
//! one-time Taproot output from our published code and broadcasts it. To find
//! that money we must read the chain ourselves — no address to watch, no
//! gap-limit descriptor to sync. This walks blocks from a checkpoint to the
//! tip, reconstructs each transaction's input public keys, and runs the
//! BIP-352 receive check with our scan key.
//!
//! Esplora's JSON `/tx` view carries prevout scriptPubKeys and witnesses, which
//! is exactly enough to recover input keys, so no special silent-payment index
//! is needed on signet. We query it directly with `minreq` (the bdk esplora
//! client returns bare `Transaction`s, which lack prevouts). Only P2TR key-path
//! and P2WPKH inputs are reconstructed; any other input type is skipped, so a
//! sender mixing in P2PKH/P2SH-P2WPKH inputs would be mis-scanned. cm's own
//! sender uses P2TR, so this holds for the signet demo; mainnet wants a proper
//! tweak index. Dust outputs below the floor are ignored.

use std::error::Error;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;

use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{Parity, PublicKey, SecretKey, XOnlyPublicKey};
use bitcoin::{OutPoint, Txid};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::ledger::Ledger;
use crate::sp::{self, TxInputs};
use crate::storage;
use crate::wallet::Wallet;

/// Outputs below this are not worth the fee to ever spend; skip them.
// P2TR dust bound. Must stay <= pay::SP_MIN_SATS so anything cm sends is found.
const DUST_FLOOR: u64 = 330;
/// With no checkpoint, start this many blocks below the tip. A fresh wallet has
/// no earlier payments, so a full-chain rescan would only waste requests.
const START_LOOKBACK: u32 = 144;
/// Esplora paginates block transactions in fixed pages of 25.
const PAGE: u32 = 25;
/// Per-request timeout (seconds) so a stuck endpoint cannot hang a WATCH tick.
const TIMEOUT_SECS: u64 = 30;

/// Serializes every scan pass in this process. Two `Ledger` instances can be
/// live on the same file at once — the `cm serve` WATCH tick and a `cm_collections`
/// call both scan — and each dedups against only its own in-memory view. Holding
/// this lock for the whole read-then-append of a pass makes the two scans
/// sequential, so one can never book an output the other has already recorded.
static SCAN_LOCK: Mutex<()> = Mutex::new(());

/// What one scan pass did: the height range covered and any new payments booked.
#[derive(Debug)]
pub struct ScanReport {
    pub from_height: u32,
    pub to_height: u32,
    pub found: Vec<Found>,
}

/// A newly discovered payment to us (already recorded in the ledger).
#[derive(Debug)]
pub struct Found {
    pub txid: String,
    pub vout: u32,
    pub sats: u64,
}

/// Scan from the stored checkpoint (or `tip - START_LOOKBACK`) to the current
/// tip, booking every fresh Silent Payments output as a Pending `SpReceived`
/// and marking any of our known SP outputs that have since been spent. The
/// checkpoint only advances after a fully successful pass, so an interrupted
/// scan is retried, never silently skipped.
pub fn scan_to_tip(wallet: &Wallet, led: &mut Ledger) -> Result<ScanReport, Box<dyn Error>> {
    // Serialize concurrent scans in this process (recover a poisoned lock rather
    // than wedging scanning forever — the guarded data is only scheduling).
    let _guard = SCAN_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let base = storage::esplora_endpoint();
    let scan_sk = wallet.sp_scan_keypair()?.secret_key();
    let spend_pk = wallet.sp_spend_keypair()?.public_key();

    let tip: u32 = get_text(&format!("{base}/blocks/tip/height"))?.trim().parse()?;
    let cp_path = checkpoint_path(wallet)?;
    let start = match load_checkpoint(&cp_path)? {
        Some(h) => h + 1,
        None => tip.saturating_sub(START_LOOKBACK),
    };

    let mut found = Vec::new();
    let mut height = start;
    while height <= tip {
        let hash = get_text(&format!("{base}/block-height/{height}"))?.trim().to_string();
        let mut page_start = 0u32;
        loop {
            let txs: Vec<EsploraTx> =
                get_json(&format!("{base}/block/{hash}/txs/{page_start}"))?;
            if txs.is_empty() {
                break;
            }
            let n = txs.len() as u32;
            for tx in &txs {
                for f in tx_matches(tx, &scan_sk, &spend_pk) {
                    if f.sats < DUST_FLOOR {
                        continue;
                    }
                    let tweak = hex_lower(&f.tweak);
                    if led.record_sp_received(&tx.txid, f.vout, f.sats, &tweak)? {
                        found.push(Found { txid: tx.txid.clone(), vout: f.vout, sats: f.sats });
                    }
                }
            }
            if n < PAGE {
                break;
            }
            page_start += n;
        }
        height += 1;
    }

    save_checkpoint(&cp_path, tip)?;
    track_spends(&base, led)?;
    Ok(ScanReport { from_height: start, to_height: tip, found })
}

/// Whether a single transaction pays us, summed over all matching outputs, with
/// no persistence. The paywall calls this to verify a claimed payment before
/// the scanner (later) books it as income.
pub fn tx_pays_me(wallet: &Wallet, txid: &str) -> Result<u64, Box<dyn Error>> {
    let base = storage::esplora_endpoint();
    let scan_sk = wallet.sp_scan_keypair()?.secret_key();
    let spend_pk = wallet.sp_spend_keypair()?.public_key();
    let tx: EsploraTx = get_json(&format!("{base}/tx/{txid}"))?;
    Ok(tx_matches(&tx, &scan_sk, &spend_pk).iter().map(|f| f.sats).sum())
}

/// Pin a freshly created wallet's first scan to the current tip by writing the
/// checkpoint at wallet birth. A new wallet has no earlier history, so anything
/// at or below the current tip is not ours. Without this anchor the first scan
/// falls back to `tip - START_LOOKBACK`, and after it saves `tip` the gap below
/// the window is never rescanned — so income received offline more than
/// `START_LOOKBACK` blocks before the first scan would be lost forever. Best
/// effort: on any failure we leave no checkpoint (the lookback fallback applies)
/// and never clobber an existing checkpoint (that would skip unscanned history).
pub fn anchor_birth(wallet: &Wallet) {
    if let Err(e) = try_anchor_birth(wallet) {
        eprintln!(
            "cm: WARN could not anchor scan birth height ({e}); \
             the first scan will use the {START_LOOKBACK}-block lookback"
        );
    }
}

fn try_anchor_birth(wallet: &Wallet) -> Result<(), Box<dyn Error>> {
    let cp_path = checkpoint_path(wallet)?;
    if cp_path.exists() {
        return Ok(());
    }
    let base = storage::esplora_endpoint();
    let tip: u32 = get_text(&format!("{base}/blocks/tip/height"))?.trim().parse()?;
    save_checkpoint(&cp_path, tip)
}

// --- matching ----------------------------------------------------------------

/// Run the BIP-352 receive check against one esplora transaction. Coinbase and
/// input-less transactions never match. Never errors: unparsable chain data
/// simply yields no matches.
fn tx_matches(tx: &EsploraTx, scan_sk: &SecretKey, spend_pk: &PublicKey) -> Vec<sp::SpFound> {
    if tx.vin.iter().any(|v| v.is_coinbase) {
        return Vec::new();
    }
    let pubkeys: Vec<PublicKey> = tx.vin.iter().filter_map(input_pubkey).collect();
    if pubkeys.is_empty() {
        return Vec::new();
    }
    // BIP-352's input hash uses the smallest outpoint over ALL inputs, not just
    // the ones whose key we could recover.
    let outpoints: Vec<OutPoint> = tx
        .vin
        .iter()
        .filter_map(|v| Some(OutPoint::new(Txid::from_str(&v.txid).ok()?, v.vout)))
        .collect();
    let smallest = match sp::smallest_outpoint(&outpoints) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let outputs: Vec<(u32, XOnlyPublicKey, u64)> = tx
        .vout
        .iter()
        .enumerate()
        .filter_map(|(i, o)| Some((i as u32, taproot_output_key(&o.scriptpubkey)?, o.value)))
        .collect();
    if outputs.is_empty() {
        return Vec::new();
    }
    let inputs = TxInputs { pubkeys, smallest_outpoint: smallest };
    sp::receive_check(&inputs, &outputs, scan_sk, spend_pk)
}

/// Reconstruct an input's public key for the BIP-352 sum, or `None` if the
/// input type is unsupported / ineligible. P2TR key-path lifts the x-only
/// output key to even Y; P2WPKH takes the 33-byte witness pubkey verbatim.
fn input_pubkey(vin: &Vin) -> Option<PublicKey> {
    if vin.is_coinbase {
        return None;
    }
    let spk = vin.prevout.as_ref()?.scriptpubkey.as_str();
    // P2TR: OP_1 <32-byte x-only> == "5120" + 64 hex.
    if let Some(key_hex) = spk.strip_prefix("5120") {
        if key_hex.len() != 64 {
            return None;
        }
        // Key-path spends only: drop an optional annex (last item, first byte
        // 0x50), then require exactly one remaining witness item. Anything more
        // is a script-path spend, whose key is not the output key.
        let mut w = vin.witness.as_slice();
        if w.len() >= 2 && w.last().is_some_and(|e| e.starts_with("50")) {
            w = &w[..w.len() - 1];
        }
        if w.len() != 1 {
            return None;
        }
        let bytes = Vec::<u8>::from_hex(key_hex).ok()?;
        let xonly = XOnlyPublicKey::from_slice(&bytes).ok()?;
        return Some(PublicKey::from_x_only_public_key(xonly, Parity::Even));
    }
    // P2WPKH: OP_0 <20-byte hash> == "0014" + 40 hex; pubkey is the last witness
    // item. The scriptPubKey hash is not needed to recover the key.
    if spk.starts_with("0014") && spk.len() == 44 {
        let pk_hex = vin.witness.last()?;
        let bytes = Vec::<u8>::from_hex(pk_hex).ok()?;
        return PublicKey::from_slice(&bytes).ok();
    }
    None
}

/// The x-only key of a P2TR output scriptPubKey, or `None` for any other type
/// (a silent-payment output is always P2TR).
fn taproot_output_key(scriptpubkey: &str) -> Option<XOnlyPublicKey> {
    let key_hex = scriptpubkey.strip_prefix("5120")?;
    if key_hex.len() != 64 {
        return None;
    }
    let bytes = Vec::<u8>::from_hex(key_hex).ok()?;
    XOnlyPublicKey::from_slice(&bytes).ok()
}

/// Mark any of our known unspent SP outputs that the chain now shows as spent.
/// Only we hold the keys, so a spend is always our own; this just keeps the
/// balance fold truthful across restarts. Idempotent.
fn track_spends(base: &str, led: &mut Ledger) -> Result<(), Box<dyn Error>> {
    for u in led.sp_utxos() {
        let os: Outspend = get_json(&format!("{base}/tx/{}/outspend/{}", u.txid, u.vout))?;
        if os.spent {
            led.record_sp_spent(&u.txid, u.vout)?;
        }
    }
    Ok(())
}

// --- checkpoint --------------------------------------------------------------

/// `scan.json` beside the ledger, holding the highest fully-scanned height.
fn checkpoint_path(wallet: &Wallet) -> Result<PathBuf, Box<dyn Error>> {
    Ok(storage::wallet_dir(wallet)?.join("scan.json"))
}

#[derive(Serialize, Deserialize)]
struct Checkpoint {
    scanned_height: u32,
}

fn load_checkpoint(path: &std::path::Path) -> Result<Option<u32>, Box<dyn Error>> {
    if !path.exists() {
        return Ok(None);
    }
    let cp: Checkpoint = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    Ok(Some(cp.scanned_height))
}

fn save_checkpoint(path: &std::path::Path, height: u32) -> Result<(), Box<dyn Error>> {
    std::fs::write(path, serde_json::to_string(&Checkpoint { scanned_height: height })?)?;
    Ok(())
}

// --- esplora JSON ------------------------------------------------------------

#[derive(Deserialize)]
struct EsploraTx {
    txid: String,
    vin: Vec<Vin>,
    vout: Vec<Vout>,
}

#[derive(Deserialize)]
struct Vin {
    txid: String,
    vout: u32,
    #[serde(default)]
    is_coinbase: bool,
    #[serde(default)]
    prevout: Option<Prevout>,
    #[serde(default)]
    witness: Vec<String>,
}

#[derive(Deserialize)]
struct Prevout {
    scriptpubkey: String,
}

#[derive(Deserialize)]
struct Vout {
    scriptpubkey: String,
    value: u64,
}

#[derive(Deserialize)]
struct Outspend {
    spent: bool,
}

fn get_text(url: &str) -> Result<String, Box<dyn Error>> {
    let resp = minreq::get(url).with_timeout(TIMEOUT_SECS).send()?;
    if resp.status_code != 200 {
        return Err(format!("GET {url} -> {}", resp.status_code).into());
    }
    Ok(resp.as_str()?.to_string())
}

fn get_json<T: DeserializeOwned>(url: &str) -> Result<T, Box<dyn Error>> {
    let resp = minreq::get(url).with_timeout(TIMEOUT_SECS).send()?;
    if resp.status_code != 200 {
        return Err(format!("GET {url} -> {}", resp.status_code).into());
    }
    Ok(serde_json::from_str(resp.as_str()?)?)
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

    fn sk(hex: &str) -> SecretKey {
        SecretKey::from_slice(&Vec::<u8>::from_hex(hex).unwrap()).unwrap()
    }

    fn vin_p2tr(key_hex: &str, witness: &[&str]) -> Vin {
        Vin {
            txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16".into(),
            vout: 0,
            is_coinbase: false,
            prevout: Some(Prevout { scriptpubkey: format!("5120{key_hex}") }),
            witness: witness.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn p2tr_keypath_reconstructs_even_y() {
        let secp = Secp256k1::new();
        let (xonly, _) = sk("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1")
            .x_only_public_key(&secp);
        let key_hex = hex_lower(&xonly.serialize());
        // Single-item witness == key-path spend: eligible.
        let got = input_pubkey(&vin_p2tr(&key_hex, &["ab".repeat(32).as_str()])).unwrap();
        assert_eq!(got, PublicKey::from_x_only_public_key(xonly, Parity::Even));
    }

    #[test]
    fn p2tr_keypath_with_annex_reconstructs() {
        let secp = Secp256k1::new();
        let (xonly, _) = sk("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1")
            .x_only_public_key(&secp);
        let key_hex = hex_lower(&xonly.serialize());
        // Two items where the last is an annex (0x50…) is still a key-path spend.
        let sig = "ab".repeat(32);
        let annex = "50aa";
        assert!(input_pubkey(&vin_p2tr(&key_hex, &[&sig, annex])).is_some());
    }

    #[test]
    fn p2tr_scriptpath_is_skipped() {
        let secp = Secp256k1::new();
        let (xonly, _) = sk("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1")
            .x_only_public_key(&secp);
        let key_hex = hex_lower(&xonly.serialize());
        // Two non-annex items == script-path spend: ineligible.
        let sig = "ab".repeat(32);
        let script = "cc".repeat(10);
        assert!(input_pubkey(&vin_p2tr(&key_hex, &[&sig, &script])).is_none());
    }

    #[test]
    fn p2wpkh_takes_witness_pubkey() {
        let secp = Secp256k1::new();
        let pk = PublicKey::from_secret_key(
            &secp,
            &sk("0000000000000000000000000000000000000000000000000000000000000003"),
        );
        let pk_hex = hex_lower(&pk.serialize());
        let vin = Vin {
            txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16".into(),
            vout: 1,
            is_coinbase: false,
            prevout: Some(Prevout { scriptpubkey: format!("0014{}", "11".repeat(20)) }),
            witness: vec!["30".repeat(35), pk_hex],
        };
        assert_eq!(input_pubkey(&vin).unwrap(), pk);
    }

    #[test]
    fn coinbase_and_unknown_types_skip() {
        let coinbase = Vin {
            txid: "0".repeat(64),
            vout: 4294967295,
            is_coinbase: true,
            prevout: None,
            witness: vec![],
        };
        assert!(input_pubkey(&coinbase).is_none());
        let p2pkh = Vin {
            txid: "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16".into(),
            vout: 0,
            is_coinbase: false,
            prevout: Some(Prevout { scriptpubkey: format!("76a914{}88ac", "11".repeat(20)) }),
            witness: vec![],
        };
        assert!(input_pubkey(&p2pkh).is_none());
    }

    // End-to-end: build the sender's one-time output with sp::send_address, wrap
    // it in an esplora tx (P2WPKH inputs + the P2TR output), and confirm the
    // scanner recovers it — exercising input reconstruction, output parsing, the
    // smallest-outpoint rule, and the sp receive check together.
    #[test]
    fn scanner_finds_a_silent_payment() {
        let secp = Secp256k1::new();
        let ik0 = sk("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1");
        let ik1 = sk("0000000000000000000000000000000000000000000000000000000000000009");
        let scan_sk = sk("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
        let spend_sk = sk("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        let op0 = OutPoint::new(
            Txid::from_str("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")
                .unwrap(),
            0,
        );
        let op1 = OutPoint::new(
            Txid::from_str("a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d")
                .unwrap(),
            2,
        );
        let inputs = vec![
            sp::SpInput { outpoint: op0, key: ik0 },
            sp::SpInput { outpoint: op1, key: ik1 },
        ];
        let addr =
            sp::send_address(&inputs, &scan_pk, &spend_pk, bitcoin::Network::Signet).unwrap();
        let out_spk = hex_lower(addr.script_pubkey().as_bytes());

        let p2wpkh_vin = |op: OutPoint, ik: &SecretKey| Vin {
            txid: op.txid.to_string(),
            vout: op.vout,
            is_coinbase: false,
            prevout: Some(Prevout { scriptpubkey: format!("0014{}", "11".repeat(20)) }),
            witness: vec![
                "30".repeat(35),
                hex_lower(&PublicKey::from_secret_key(&secp, ik).serialize()),
            ],
        };
        let tx = EsploraTx {
            txid: "b0b0000000000000000000000000000000000000000000000000000000000000".into(),
            vin: vec![p2wpkh_vin(op0, &ik0), p2wpkh_vin(op1, &ik1)],
            vout: vec![Vout { scriptpubkey: out_spk, value: 5000 }],
        };

        let found = tx_matches(&tx, &scan_sk, &spend_pk);
        assert_eq!(found.len(), 1, "the one SP output must be found");
        assert_eq!(found[0].vout, 0);
        assert_eq!(found[0].sats, 5000);
        // The recovered tweak reproduces the output key from the spend key.
        let kp = sp::spend_keypair(&spend_sk, &found[0].tweak).unwrap();
        let out_key = taproot_output_key(&tx.vout[0].scriptpubkey).unwrap();
        assert_eq!(kp.x_only_public_key().0, out_key);
    }

    #[test]
    fn checkpoint_round_trip() {
        let mut path = std::env::temp_dir();
        path.push(format!("cm_scan_cp_{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert_eq!(load_checkpoint(&path).unwrap(), None);
        save_checkpoint(&path, 12345).unwrap();
        assert_eq!(load_checkpoint(&path).unwrap(), Some(12345));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn smallest_outpoint_matches_bip352_ordering() {
        // Same txid, different vout: the smaller vout wins (little-endian vout,
        // but 0 < 2 either way). Confirms our usage of sp::smallest_outpoint.
        let txid =
            Txid::from_str("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")
                .unwrap();
        let a = OutPoint::new(txid, 0);
        let b = OutPoint::new(txid, 2);
        assert_eq!(sp::smallest_outpoint(&[b, a]), Some(a));
    }
}
