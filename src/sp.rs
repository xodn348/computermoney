//! sp — BIP-352 Silent Payments math and address encoding. Pure and I/O-free.
//!
//! One published static code (`sp1…`/`tsp1…`) lets a payer derive a fresh
//! one-time Taproot output for the receiver, so the receiver is paid without
//! reusing an address and without being online. This module is the whole
//! cryptographic core: derive a send address from the chosen inputs, scan a
//! transaction's outputs for payments to us, and reconstruct the spend key of
//! a payment we found. It holds no wallet or chain state — callers supply the
//! keys and outpoints, keeping the money-deciding code small and testable.
//!
//! Hand-rolled over `bitcoin::secp256k1` (no `silentpayments` crate: it has no
//! stable release and would pin its own secp version). Verified against the
//! BIP-352 official send/receive test vectors (see the tests below).

use bitcoin::key::TweakedPublicKey;
use bitcoin::secp256k1::{
    All, Keypair, Parity, PublicKey, Scalar, Secp256k1, SecretKey, XOnlyPublicKey,
};
use bitcoin::{Address, KnownHrp, Network, OutPoint};

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};

/// BIP-352 tagged-hash tags.
const TAG_INPUTS: &[u8] = b"BIP0352/Inputs";
const TAG_SHARED: &[u8] = b"BIP0352/SharedSecret";

/// A transaction input the *sender* contributes, with its spend key already
/// normalized: for a Taproot key-path input the key must be the even-Y form
/// (see [`taproot_input_key`]); a P2WPKH key is used as-is. `outpoint` feeds
/// the BIP-352 input hash.
pub struct SpInput {
    pub outpoint: OutPoint,
    pub key: SecretKey,
}

/// The *receiver*'s view of a transaction's inputs: every input public key we
/// could reconstruct (Taproot keys lifted to even Y, P2WPKH keys verbatim) and
/// the lexicographically smallest input outpoint. Together they reproduce the
/// same shared secret the sender used.
pub struct TxInputs {
    pub pubkeys: Vec<PublicKey>,
    pub smallest_outpoint: OutPoint,
}

/// A payment to us found in one transaction: which output, its value, and the
/// tweak `t_k` such that the spend key is `b_spend + t_k` (mod n).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpFound {
    pub vout: u32,
    pub sats: u64,
    pub tweak: [u8; 32],
}

/// Encode a silent-payment code: `sp1…` on mainnet, `tsp1…` elsewhere. The
/// payload is `scan(33) || spend(33)` compressed pubkeys, bech32m with a
/// leading version-0 element (so the string starts `…1q…`). The 90-char
/// bech32 length limit does not apply to SP codes.
pub fn encode(scan: &PublicKey, spend: &PublicKey, network: Network) -> String {
    let hrp = Hrp::parse(hrp_str(network)).expect("static hrp is valid");
    let mut payload = Vec::with_capacity(66);
    payload.extend_from_slice(&scan.serialize());
    payload.extend_from_slice(&spend.serialize());
    payload
        .iter()
        .copied()
        .bytes_to_fes()
        .with_checksum::<Bech32m>(&hrp)
        .with_witness_version(Fe32::Q) // version 0
        .chars()
        .collect()
}

/// Decode an `sp1…`/`tsp1…` code back to (scan, spend, network). `tsp` maps to
/// signet — cm's only non-mainnet network — so a mainnet/non-mainnet mismatch
/// is caught by the caller comparing against its wallet network.
pub fn decode(code: &str) -> Result<(PublicKey, PublicKey, Network), Error> {
    let checked = CheckedHrpstring::new::<Bech32m>(code.trim())
        .map_err(|e| Error::Encoding(format!("bad bech32m: {e}")))?;
    let network = match checked.hrp().to_lowercase().as_str() {
        "sp" => Network::Bitcoin,
        "tsp" => Network::Signet,
        other => return Err(Error::Encoding(format!("unknown sp hrp '{other}'"))),
    };
    let mut fes = checked.fe32_iter::<std::vec::IntoIter<u8>>();
    let version = fes.next().ok_or(Error::Encoding("empty sp payload".into()))?;
    if version != Fe32::Q {
        return Err(Error::Encoding("unsupported sp version".into()));
    }
    let bytes: Vec<u8> = fes.fes_to_bytes().collect();
    if bytes.len() != 66 {
        return Err(Error::Encoding(format!("sp payload is {} bytes, want 66", bytes.len())));
    }
    let scan = PublicKey::from_slice(&bytes[..33])?;
    let spend = PublicKey::from_slice(&bytes[33..])?;
    Ok((scan, spend, network))
}

/// Normalize a Taproot key-path input's private key to the even-Y form BIP-352
/// requires (a Taproot output key is x-only, i.e. implicitly even Y). P2WPKH
/// and other keys must NOT be passed through this. Used by the sender when
/// building [`SpInput`]s.
pub fn taproot_input_key(sk: SecretKey) -> SecretKey {
    let secp = Secp256k1::new();
    let (_, parity) = PublicKey::from_secret_key(&secp, &sk).x_only_public_key();
    match parity {
        Parity::Odd => sk.negate(),
        Parity::Even => sk,
    }
}

/// The lexicographically smallest outpoint by 36-byte consensus serialization
/// (`txid || vout_le`), per BIP-352. `None` for an empty slice.
pub fn smallest_outpoint(outpoints: &[OutPoint]) -> Option<OutPoint> {
    outpoints
        .iter()
        .copied()
        .min_by(|a, b| ser_outpoint(a).cmp(&ser_outpoint(b)))
}

/// Derive the receiver's one-time Taproot address for output index 0 from the
/// sender's chosen inputs. The output key is used verbatim as the Taproot
/// output key (no BIP-341 tweak), which is why this builds the address via
/// `p2tr_tweaked`/`dangerous_assume_tweaked` rather than `p2tr`.
pub fn send_address(
    inputs: &[SpInput],
    scan: &PublicKey,
    spend: &PublicKey,
    network: Network,
) -> Result<Address, Error> {
    let secp = Secp256k1::new();
    let (a_sum, input_hash) = sender_context(&secp, inputs)?;
    // ecdh = input_hash * a_sum * B_scan
    let partial = a_sum.mul_tweak(&scalar(&input_hash)?)?;
    let ecdh = (*scan).mul_tweak(&secp, &scalar(&partial.secret_bytes())?)?;
    let (xonly, _tweak) = output_at(&secp, &ecdh, spend, 0)?;
    let tweaked = TweakedPublicKey::dangerous_assume_tweaked(xonly);
    Ok(Address::p2tr_tweaked(tweaked, known_hrp(network)))
}

/// Scan one transaction's outputs for payments to us. Returns every matching
/// output with its recovered tweak, in ascending derivation order. Never
/// errors: a transaction whose inputs we cannot make sense of simply yields no
/// matches (this runs over arbitrary chain data). No dust filtering — that is
/// the scanner's policy, not the math's.
pub fn receive_check(
    inputs: &TxInputs,
    outputs: &[(u32, XOnlyPublicKey, u64)],
    scan_sk: &SecretKey,
    spend_pk: &PublicKey,
) -> Vec<SpFound> {
    receive_inner(inputs, outputs, scan_sk, spend_pk).unwrap_or_default()
}

/// Reconstruct the spend keypair of a found payment: `d = b_spend + t_k`
/// (mod n). Recoverable from the seed's spend key plus the stored tweak alone.
pub fn spend_keypair(spend_sk: &SecretKey, tweak: &[u8; 32]) -> Result<Keypair, Error> {
    let secp = Secp256k1::new();
    let d = spend_sk.add_tweak(&scalar(tweak)?)?;
    Ok(Keypair::from_secret_key(&secp, &d))
}

// --- internals ---------------------------------------------------------------

/// Sum the sender's input keys into `a_sum` and derive the BIP-352 input hash.
fn sender_context(secp: &Secp256k1<All>, inputs: &[SpInput]) -> Result<(SecretKey, [u8; 32]), Error> {
    let (first, rest) = inputs.split_first().ok_or(Error::NoInputs)?;
    let mut a_sum = first.key;
    for inp in rest {
        a_sum = a_sum.add_tweak(&scalar(&inp.key.secret_bytes())?)?;
    }
    let outpoints: Vec<OutPoint> = inputs.iter().map(|i| i.outpoint).collect();
    let smallest = smallest_outpoint(&outpoints).ok_or(Error::NoInputs)?;
    let a_pub = PublicKey::from_secret_key(secp, &a_sum);
    Ok((a_sum, input_hash(&smallest, &a_pub)))
}

fn receive_inner(
    inputs: &TxInputs,
    outputs: &[(u32, XOnlyPublicKey, u64)],
    scan_sk: &SecretKey,
    spend_pk: &PublicKey,
) -> Result<Vec<SpFound>, Error> {
    let (first, rest) = inputs.pubkeys.split_first().ok_or(Error::NoInputs)?;
    let secp = Secp256k1::new();
    let mut a_sum = *first;
    for pk in rest {
        a_sum = a_sum.combine(pk)?;
    }
    let ih = input_hash(&inputs.smallest_outpoint, &a_sum);
    // ecdh = input_hash * b_scan * A_sum
    let partial = scan_sk.mul_tweak(&scalar(&ih)?)?;
    let ecdh = a_sum.mul_tweak(&secp, &scalar(&partial.secret_bytes())?)?;

    let mut remaining: Vec<(u32, XOnlyPublicKey, u64)> = outputs.to_vec();
    let mut found = Vec::new();
    let mut k: u32 = 0;
    while !remaining.is_empty() {
        let (xonly, tweak) = output_at(&secp, &ecdh, spend_pk, k)?;
        match remaining.iter().position(|(_, x, _)| *x == xonly) {
            Some(pos) => {
                let (vout, _, sats) = remaining.remove(pos);
                found.push(SpFound { vout, sats, tweak });
                k += 1;
            }
            None => break,
        }
    }
    Ok(found)
}

/// Output key and tweak at index `k`: `t_k = H(ecdh || ser32(k))`, `P_k =
/// B_spend + t_k*G`, returned x-only alongside `t_k`.
fn output_at(
    secp: &Secp256k1<All>,
    ecdh: &PublicKey,
    spend: &PublicKey,
    k: u32,
) -> Result<(XOnlyPublicKey, [u8; 32]), Error> {
    let mut msg = Vec::with_capacity(37);
    msg.extend_from_slice(&ecdh.serialize());
    msg.extend_from_slice(&k.to_be_bytes());
    let t_k = tagged_hash(TAG_SHARED, &msg);
    let t_sk = SecretKey::from_slice(&t_k)?;
    let t_point = PublicKey::from_secret_key(secp, &t_sk);
    let p_k = spend.combine(&t_point)?;
    Ok((p_k.x_only_public_key().0, t_k))
}

fn input_hash(smallest: &OutPoint, a_sum_pub: &PublicKey) -> [u8; 32] {
    let mut msg = ser_outpoint(smallest); // 36 bytes
    msg.extend_from_slice(&a_sum_pub.serialize()); // 33 bytes
    tagged_hash(TAG_INPUTS, &msg)
}

fn ser_outpoint(o: &OutPoint) -> Vec<u8> {
    bitcoin::consensus::encode::serialize(o)
}

fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash, HashEngine};
    let tag_hash = sha256::Hash::hash(tag);
    let mut eng = sha256::Hash::engine();
    eng.input(tag_hash.as_ref());
    eng.input(tag_hash.as_ref());
    eng.input(msg);
    sha256::Hash::from_engine(eng).to_byte_array()
}

fn scalar(bytes: &[u8; 32]) -> Result<Scalar, Error> {
    Scalar::from_be_bytes(*bytes).map_err(|_| Error::Scalar)
}

fn hrp_str(network: Network) -> &'static str {
    if network == Network::Bitcoin {
        "sp"
    } else {
        "tsp"
    }
}

fn known_hrp(network: Network) -> KnownHrp {
    if network == Network::Bitcoin {
        KnownHrp::Mainnet
    } else {
        KnownHrp::Testnets
    }
}

#[derive(Debug)]
pub enum Error {
    Secp(bitcoin::secp256k1::Error),
    /// A derived scalar was out of range (astronomically unlikely).
    Scalar,
    NoInputs,
    Encoding(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Secp(e) => write!(f, "secp256k1: {e}"),
            Error::Scalar => write!(f, "silent-payment scalar out of range"),
            Error::NoInputs => write!(f, "silent payment needs at least one input"),
            Error::Encoding(m) => write!(f, "silent-payment code: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<bitcoin::secp256k1::Error> for Error {
    fn from(e: bitcoin::secp256k1::Error) -> Self {
        Error::Secp(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // A representative handful of BIP-352 official send/receive vectors, pinned
    // by hand (the full file has 28 groups built around whole transactions).
    // Each entry: inputs (priv key hex, is-taproot, txid, vout), recipient
    // scan/spend pubkey hex, and expected one-time output x-only keys.
    struct Vec352 {
        inputs: &'static [(&'static str, bool, &'static str, u32)],
        scan: &'static str,
        spend: &'static str,
        outputs: &'static [&'static str],
    }

    // Recipient is the same across the pinned vectors (BIP-352's example addr).
    const SCAN: &str = "0220bcfac5b99e04ad1a06ddfb016ee13582609d60b6291e98d01a9bc9a16c96d4";
    const SPEND: &str = "025cc9856d6f8375350e123978daac200c260cb5b5ae83106cab90484dcd8fcf36";
    const ADDR: &str = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
    const TXID_A: &str = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";
    const TXID_B: &str = "a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d";

    // V0: two P2WPKH inputs.
    const V0: Vec352 = Vec352 {
        inputs: &[
            ("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1", false, TXID_A, 0),
            ("93f5ed907ad5b2bdbbdcb5d9116ebc0a4e1f92f910d5260237fa45a9408aad16", false, TXID_B, 0),
        ],
        scan: SCAN,
        spend: SPEND,
        outputs: &["3e9fce73d4e77a4809908e3c3a2e54ee147b9312dc5044a193d1fc85de46e3c1"],
    };
    // V6: two Taproot inputs, both even-Y.
    const V6: Vec352 = Vec352 {
        inputs: &[
            ("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1", true, TXID_A, 0),
            ("fc8716a97a48ba9a05a98ae47b5cd201a25a7fd5d8b73c203c5f7b6b6b3b6ad7", true, TXID_B, 0),
        ],
        scan: SCAN,
        spend: SPEND,
        outputs: &["de88bea8e7ffc9ce1af30d1132f910323c505185aec8eae361670421e749a1fb"],
    };
    // V7: two Taproot inputs, mixed even/odd Y — exercises even-Y negation.
    const V7: Vec352 = Vec352 {
        inputs: &[
            ("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1", true, TXID_A, 0),
            ("1d37787c2b7116ee983e9f9c13269df29091b391c04db94239e0d2bc2182c3bf", true, TXID_B, 0),
        ],
        scan: SCAN,
        spend: SPEND,
        outputs: &["77cab7dd12b10259ee82c6ea4b509774e33e7078e7138f568092241bf26b99f1"],
    };
    // V10: two P2WPKH inputs, two outputs to the same recipient (k = 0, 1).
    const V10: Vec352 = Vec352 {
        inputs: &[
            ("eadc78165ff1f8ea94ad7cfdc54990738a4c53f6e0507b42154201b8e5dff3b1", false, TXID_A, 0),
            ("0378e95685b74565fa56751b84a32dfd18545d10d691641b8372e32164fad66a", false, TXID_B, 0),
        ],
        scan: SCAN,
        spend: SPEND,
        outputs: &[
            "e976a58fbd38aeb4e6093d4df02e9c1de0c4513ae0c588cef68cda5b2f8834ca",
            "f207162b1a7abc51c42017bef055e9ec1efc3d3567cb720357e2b84325db33ac",
        ],
    };

    fn sk(hex: &str) -> SecretKey {
        SecretKey::from_slice(&hex_bytes(hex)).unwrap()
    }
    fn xonly(hex: &str) -> XOnlyPublicKey {
        XOnlyPublicKey::from_slice(&hex_bytes(hex)).unwrap()
    }
    fn pk(hex: &str) -> PublicKey {
        PublicKey::from_slice(&hex_bytes(hex)).unwrap()
    }
    fn hex_bytes(h: &str) -> Vec<u8> {
        (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
    }
    fn outpoint(txid: &str, vout: u32) -> OutPoint {
        OutPoint::new(bitcoin::Txid::from_str(txid).unwrap(), vout)
    }

    // Sender: derive the one-time output address and check it matches the
    // address built from the spec's expected output key. Anchors the send
    // math (including even-Y negation on V7) against BIP-352.
    fn check_send(v: &Vec352) {
        let inputs: Vec<SpInput> = v
            .inputs
            .iter()
            .map(|(k, taproot, txid, vout)| {
                let key = sk(k);
                let key = if *taproot { taproot_input_key(key) } else { key };
                SpInput { outpoint: outpoint(txid, *vout), key }
            })
            .collect();
        let addr = send_address(&inputs, &pk(v.scan), &pk(v.spend), Network::Bitcoin).unwrap();
        let want = Address::p2tr_tweaked(
            TweakedPublicKey::dangerous_assume_tweaked(xonly(v.outputs[0])),
            KnownHrp::Mainnet,
        );
        assert_eq!(addr, want, "send address mismatch for a pinned vector");
    }

    #[test]
    fn send_p2wpkh_matches_vector() {
        check_send(&V0);
    }
    #[test]
    fn send_taproot_even_matches_vector() {
        check_send(&V6);
    }
    #[test]
    fn send_taproot_mixed_parity_matches_vector() {
        check_send(&V7);
    }

    // Receiver: with the same inputs (P2WPKH pubkeys derived from the keys) and
    // the recipient scan key, receive_check must find every output and recover
    // the exact tweak the spec lists.
    #[test]
    fn receive_recovers_outputs_and_tweaks() {
        let secp = Secp256k1::new();
        let scan_sk = sk("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
        let spend_pk = pk(SPEND);
        for v in [&V0, &V10] {
            let pubs: Vec<PublicKey> =
                v.inputs.iter().map(|(k, _, _, _)| PublicKey::from_secret_key(&secp, &sk(k))).collect();
            let ops: Vec<OutPoint> =
                v.inputs.iter().map(|(_, _, txid, vout)| outpoint(txid, *vout)).collect();
            let tx = TxInputs { pubkeys: pubs, smallest_outpoint: smallest_outpoint(&ops).unwrap() };
            let outs: Vec<(u32, XOnlyPublicKey, u64)> =
                v.outputs.iter().enumerate().map(|(i, o)| (i as u32, xonly(o), 1000)).collect();
            let found = receive_check(&tx, &outs, &scan_sk, &spend_pk);
            assert_eq!(found.len(), v.outputs.len(), "wrong match count");
            // Matches come back in derivation (k) order, which need not equal
            // output order — so pair each found payment with the output at its
            // own recorded vout. The recovered tweak must reproduce that output
            // key from the spend key: pubkey(b_spend + t_k) x-only == output.
            let spend_sk =
                sk("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");
            for f in &found {
                let kp = spend_keypair(&spend_sk, &f.tweak).unwrap();
                assert_eq!(
                    kp.x_only_public_key().0,
                    xonly(v.outputs[f.vout as usize]),
                    "spend key does not reproduce the matched output at its vout"
                );
            }
        }
    }

    // Receiver, Taproot inputs: the scanner lifts each input's x-only key to
    // even Y (a Taproot scriptPubKey carries the even-Y x-only key), and the
    // sender normalized the same keys to even Y, so both sums agree. V7 mixes
    // input parities, exercising that lift on the receive side — the all-P2TR
    // path (cm's own) with an offline spec anchor, not just live signet.
    #[test]
    fn receive_recovers_from_taproot_inputs() {
        let secp = Secp256k1::new();
        let scan_sk = sk("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
        let spend_sk = sk("9d6ad855ce3417ef84e836892e5a56392bfba05fa5d97ccea30e266f540e08b3");
        let spend_pk = pk(SPEND);
        let pubs: Vec<PublicKey> = V7
            .inputs
            .iter()
            .map(|(k, _, _, _)| {
                let (xo, _) = sk(k).x_only_public_key(&secp);
                PublicKey::from_x_only_public_key(xo, bitcoin::secp256k1::Parity::Even)
            })
            .collect();
        let ops: Vec<OutPoint> = V7.inputs.iter().map(|(_, _, t, v)| outpoint(t, *v)).collect();
        let tx = TxInputs { pubkeys: pubs, smallest_outpoint: smallest_outpoint(&ops).unwrap() };
        let outs = vec![(0u32, xonly(V7.outputs[0]), 1000u64)];
        let found = receive_check(&tx, &outs, &scan_sk, &spend_pk);
        assert_eq!(found.len(), 1, "the taproot-input payment must be found");
        let kp = spend_keypair(&spend_sk, &found[0].tweak).unwrap();
        assert_eq!(kp.x_only_public_key().0, xonly(V7.outputs[0]));
    }

    #[test]
    fn known_tweak_values_match_spec() {
        // Anchor the actual tweak bytes for V0's single output.
        let secp = Secp256k1::new();
        let scan_sk = sk("0f694e068028a717f8af6b9411f9a133dd3565258714cc226594b34db90c1f2c");
        let spend_pk = pk(SPEND);
        let pubs: Vec<PublicKey> =
            V0.inputs.iter().map(|(k, _, _, _)| PublicKey::from_secret_key(&secp, &sk(k))).collect();
        let ops: Vec<OutPoint> = V0.inputs.iter().map(|(_, _, t, v)| outpoint(t, *v)).collect();
        let tx = TxInputs { pubkeys: pubs, smallest_outpoint: smallest_outpoint(&ops).unwrap() };
        let outs = vec![(0u32, xonly(V0.outputs[0]), 1000u64)];
        let found = receive_check(&tx, &outs, &scan_sk, &spend_pk);
        assert_eq!(
            hex::encode_lower(found[0].tweak),
            "f438b40179a3c4262de12986c0e6cce0634007cdc79c1dcd3e20b9ebc2e7eef6"
        );
    }

    #[test]
    fn encode_decode_round_trip() {
        let scan = pk(SCAN);
        let spend = pk(SPEND);
        let code = encode(&scan, &spend, Network::Bitcoin);
        assert_eq!(code, ADDR, "encoded code must match the BIP-352 example address");
        let (s, p, net) = decode(&code).unwrap();
        assert_eq!(s, scan);
        assert_eq!(p, spend);
        assert_eq!(net, Network::Bitcoin);
        // Signet uses the tsp hrp.
        let tcode = encode(&scan, &spend, Network::Signet);
        assert!(tcode.starts_with("tsp1q"), "signet code should be tsp1q…, got {tcode}");
        assert_eq!(decode(&tcode).unwrap().2, Network::Signet);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode("not a code").is_err());
        assert!(decode("sp1qqqqqqqqqq").is_err()); // bad checksum / short
    }
}

// Minimal lowercase-hex encoder for the one test that pins tweak bytes; keeps a
// hex crate out of the dependency set.
#[cfg(test)]
mod hex {
    pub fn encode_lower(bytes: [u8; 32]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(64);
        for b in bytes {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}
