//! key-genesis — a visual walkthrough of how `cm` derives every key.
//!
//! Prints each stage of the wallet's key genesis: one CSPRNG draw ->
//! BIP-39 word slicing -> PBKDF2 seed -> BIP-32 master key -> the four
//! BIP-86 branches (receive / change / ledger-signing / WireGuard
//! identity). The derivation mirrors `src/wallet.rs` exactly, on signet
//! (coin type 1'), so the printed `cm id` and addresses match what a
//! signet `cm` wallet would produce from the same mnemonic.
//!
//! Run:  cargo run --example key-genesis
//!       CM_MNEMONIC="12 words ..." cargo run --example key-genesis
//!
//! With CM_MNEMONIC set it reproduces that wallet's keys and does NOT
//! print the words, so it is safe to run against a real wallet.

use std::str::FromStr;

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::key::Secp256k1;
use bitcoin::{Address, KnownHrp, Network};
use rand::RngCore;
use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn bits(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:08b}")).collect()
}

fn main() {
    let secp = Secp256k1::new();

    let (mnemonic, from_env) = match std::env::var("CM_MNEMONIC") {
        Ok(phrase) => (Mnemonic::from_str(phrase.trim()).expect("bad mnemonic"), true),
        Err(_) => {
            // Stage 1: the ONLY randomness in the wallet's life.
            let mut entropy = [0u8; 16];
            rand::rngs::OsRng.fill_bytes(&mut entropy); // OS CSPRNG, 128 bits
            (Mnemonic::from_entropy(&entropy).unwrap(), false)
        }
    };

    if from_env {
        println!("[reproduce mode] deriving from CM_MNEMONIC (words not shown)\n");
    } else {
        let (arr, len) = mnemonic.to_entropy_array();
        let entropy = &arr[..len];
        println!("STAGE 1 — entropy: one draw from the OS CSPRNG (getrandom)");
        println!("  128 bits: {}", hex(entropy));
        println!("  binary  : {}\n", bits(entropy));

        // Stage 2: entropy -> words. SHA-256 checksum, then 11-bit slices.
        let check = Sha256::digest(entropy);
        println!("STAGE 2 — BIP-39: bits become words");
        println!("  checksum = first 4 bits of SHA-256(entropy) = {:04b}", check[0] >> 4);
        println!("  128 + 4 = 132 bits, cut into 12 slices of 11 bits;");
        println!("  each slice is an index into the 2048-word list:\n");

        let mut all_bits = bits(entropy);
        all_bits.push_str(&format!("{:04b}", check[0] >> 4));
        for (i, word) in mnemonic.words().enumerate() {
            let slice = &all_bits[i * 11..(i + 1) * 11];
            let index = u16::from_str_radix(slice, 2).unwrap();
            println!("  word {:2}: {} = {:4}  ->  {}", i + 1, slice, index, word);
        }
        println!();
    }

    // Stage 3: words -> 512-bit seed (PBKDF2-HMAC-SHA512, 2048 rounds).
    let seed = mnemonic.to_seed("");
    println!("STAGE 3 — PBKDF2-HMAC-SHA512(words, 2048 rounds) -> 512-bit seed");
    println!("  seed: {}…{}\n", &hex(&seed)[..32], &hex(&seed)[96..]);

    // Stage 4: seed -> BIP-32 master key.
    let root = Xpriv::new_master(Network::Signet, &seed).unwrap();
    println!("STAGE 4 — HMAC-SHA512(\"Bitcoin seed\", seed) -> master xpriv");
    println!("  fingerprint: {}\n", root.fingerprint(&secp));

    // Stage 5: one root, four branches (BIP-86, signet coin type 1').
    println!("STAGE 5 — the tree forks: m/86'/1'/0'/<branch>/<index>");

    for n in 0..2 {
        let path = DerivationPath::from_str(&format!("m/86'/1'/0'/0/{n}")).unwrap();
        let child = root.derive_priv(&secp, &path).unwrap();
        let (xonly, _) = child.to_keypair(&secp).x_only_public_key();
        let addr = Address::p2tr(&secp, xonly, None, KnownHrp::Testnets);
        println!("  branch 0 (receive) index {n}:  {path}");
        println!("      -> Taproot address {addr}");
    }

    let path = DerivationPath::from_str("m/86'/1'/0'/1/0").unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    let (xonly, _) = child.to_keypair(&secp).x_only_public_key();
    let change = Address::p2tr(&secp, xonly, None, KnownHrp::Testnets);
    println!("  branch 1 (change)  index 0:  {path}");
    println!("      -> Taproot address {change}");

    let path = DerivationPath::from_str("m/86'/1'/0'/2/0").unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    let (sign_pub, _) = child.to_keypair(&secp).x_only_public_key();
    println!("  branch 2 (ledger-signing key, secp256k1 Schnorr):");
    println!("      -> pubkey {sign_pub}");

    let path = DerivationPath::from_str("m/86'/1'/0'/3/0").unwrap();
    let child = root.derive_priv(&secp, &path).unwrap();
    let wg_secret = boringtun::x25519::StaticSecret::from(child.private_key.secret_bytes());
    let wg_public = boringtun::x25519::PublicKey::from(&wg_secret);
    println!("  branch 3 (WireGuard identity, X25519):");
    println!("      -> cm id = {}", hex(wg_public.as_bytes()));

    println!("\none 128-bit draw -> money keys + signing key + network identity.");
}
