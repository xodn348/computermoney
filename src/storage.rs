//! storage — encrypted seed at rest.
//!
//! Milestone 1 read the mnemonic from a plaintext env var (CM_MNEMONIC).
//! That is fine for a signet demo and unacceptable for real funds. This
//! module seals the mnemonic with a passphrase: Argon2id stretches the
//! passphrase into a 32-byte key, ChaCha20-Poly1305 encrypts the
//! mnemonic under it. The on-disk file is salt || nonce || ciphertext —
//! a wrong passphrase or any tampering fails the AEAD tag, so it cannot
//! silently return garbage.
//!
//! Argon2id is memory-hard, so a stolen seed file resists offline
//! brute-force far better than a fast hash would.

use std::error::Error;
use std::path::{Path, PathBuf};

use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use zeroize::Zeroizing;

use bitcoin::Network;

use crate::wallet::Wallet;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Encrypt `mnemonic` under `passphrase` and write to `path`.
pub fn save_encrypted(mnemonic: &str, passphrase: &str, path: &Path) -> Result<(), Box<dyn Error>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    let key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), mnemonic.as_bytes())
        .map_err(|_| "encryption failed")?;

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    std::fs::write(path, out)?;
    Ok(())
}

/// Read and decrypt the seed file at `path` using `passphrase`. Returns
/// an error (not garbage) on a wrong passphrase or a tampered file.
pub fn load_encrypted(passphrase: &str, path: &Path) -> Result<Zeroizing<String>, Box<dyn Error>> {
    let data = std::fs::read(path)?;
    if data.len() < SALT_LEN + NONCE_LEN {
        return Err("seed file is truncated".into());
    }
    let (salt, rest) = data.split_at(SALT_LEN);
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);

    let key = derive_key(passphrase, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| "decryption failed — wrong passphrase or corrupt file")?;
    // from_utf8 reuses the plaintext allocation; Zeroizing wipes it on drop.
    Ok(Zeroizing::new(String::from_utf8(plaintext)?))
}

/// Argon2id: passphrase + salt -> 32-byte key. The returned key zeroizes
/// itself on drop so it does not linger after the cipher is built.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, Box<dyn Error>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Where the encrypted seed lives. `CM_SEED` overrides; otherwise
/// `~/.config/computermoney/seed.enc`.
pub fn seed_path() -> PathBuf {
    config_path("CM_SEED", "seed.enc")
}

/// Where the plaintext mnemonic lives in the no-passphrase test-network
/// flow: `mnemonic`, next to the seed file (so `CM_SEED` relocates both).
/// Real funds never touch this path — `load_wallet` refuses it on mainnet.
pub fn mnemonic_path() -> PathBuf {
    seed_path().with_file_name("mnemonic")
}

/// Persist a plaintext mnemonic (owner-only 0600) for the no-passphrase
/// test-network flow. Callers gate on a non-mainnet network.
pub fn save_plaintext_mnemonic(mnemonic: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = mnemonic_path();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, format!("{mnemonic}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(path)
}

/// Where this agent's append-only ledger lives. `CM_LEDGER` overrides;
/// otherwise `~/.config/computermoney/ledger.jsonl`.
pub fn ledger_path() -> PathBuf {
    config_path("CM_LEDGER", "ledger.jsonl")
}

/// Resolve an env override or `~/.config/computermoney/<file>`.
pub(crate) fn config_path(env_key: &str, file: &str) -> PathBuf {
    if let Ok(p) = std::env::var(env_key) {
        return PathBuf::from(p);
    }
    let mut p = std::env::var("HOME").map(PathBuf::from).unwrap_or_default();
    p.push(".config");
    p.push("computermoney");
    p.push(file);
    p
}

/// Active Bitcoin network. `CM_NETWORK` = `mainnet` (default) | `testnet` |
/// `signet`. Mainnet is the default because that is what real users run; a
/// demo opts down to testnet/signet explicitly.
pub fn network() -> Network {
    match std::env::var("CM_NETWORK")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        _ => Network::Bitcoin,
    }
}

/// Short label for the active network, for human-facing messages.
pub fn network_label() -> &'static str {
    match network() {
        Network::Testnet => "testnet",
        Network::Signet => "signet",
        _ => "mainnet",
    }
}

/// Esplora endpoint for the active network. `CM_ESPLORA` overrides; otherwise
/// a public default per network (signet points at mutinynet's 30-second-block
/// esplora, which is convenient for fast demos).
pub fn esplora_endpoint() -> String {
    if let Ok(e) = std::env::var("CM_ESPLORA") {
        let e = e.trim();
        if !e.is_empty() {
            return e.to_string();
        }
    }
    match network() {
        Network::Testnet => "https://blockstream.info/testnet/api".to_string(),
        Network::Signet => "https://mutinynet.com/api".to_string(),
        _ => "https://blockstream.info/api".to_string(),
    }
}

/// A block-explorer URL for a txid on the active network, for messages.
pub fn explorer_tx_url(txid: &str) -> String {
    let base = match network() {
        Network::Testnet => "https://mempool.space/testnet/tx/",
        Network::Signet => "https://mutinynet.com/tx/",
        _ => "https://mempool.space/tx/",
    };
    format!("{base}{txid}")
}

/// Load the signing wallet. Prefers the encrypted seed file (unlocked
/// with `CM_PASSPHRASE`); falls back to a plaintext `CM_MNEMONIC` env var,
/// then to the plaintext mnemonic file — both for test networks only.
/// Errors if nothing is available.
pub fn load_wallet() -> Result<Wallet, Box<dyn Error>> {
    let path = seed_path();
    if path.exists() {
        let pass = std::env::var("CM_PASSPHRASE")
            .map_err(|_| "encrypted seed found; set CM_PASSPHRASE to unlock")?;
        let phrase = load_encrypted(&pass, &path)?; // Zeroizing<String>
        return Ok(Wallet::from_mnemonic(phrase.as_str())?);
    }
    if let Ok(phrase) = std::env::var("CM_MNEMONIC") {
        let phrase = Zeroizing::new(phrase); // wipe our copy on drop
        return Ok(Wallet::from_mnemonic(phrase.as_str())?);
    }
    let mn_path = mnemonic_path();
    if mn_path.exists() {
        // A bare key on disk is a test-network convenience, never a way to
        // hold real funds: on mainnet it is refused, not silently used.
        if network() == Network::Bitcoin {
            return Err("plaintext mnemonic file found, refused on mainnet — \
                        seal it with `cm init` + CM_PASSPHRASE instead"
                .into());
        }
        let phrase = Zeroizing::new(std::fs::read_to_string(&mn_path)?);
        return Ok(Wallet::from_mnemonic(phrase.as_str())?);
    }
    Err("no wallet: run `cm init` (or `cm setup`) first — on mainnet set CM_PASSPHRASE to seal the seed".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("cm_seed_test_{name}_{}.enc", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    const MNEMONIC: &str = "current claim robot field pony unveil embody soda clever mix buffalo excess";

    #[test]
    fn round_trip_correct_passphrase() {
        let path = temp_path("ok");
        save_encrypted(MNEMONIC, "hunter2-correct-horse", &path).unwrap();
        let got = load_encrypted("hunter2-correct-horse", &path).unwrap();
        assert_eq!(got.as_str(), MNEMONIC);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn wrong_passphrase_fails_not_garbage() {
        let path = temp_path("wrong");
        save_encrypted(MNEMONIC, "right-pass", &path).unwrap();
        assert!(load_encrypted("WRONG-pass", &path).is_err());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let path = temp_path("tamper");
        save_encrypted(MNEMONIC, "pass", &path).unwrap();
        let mut data = std::fs::read(&path).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0xff; // flip a ciphertext byte
        std::fs::write(&path, &data).unwrap();
        assert!(load_encrypted("pass", &path).is_err(), "AEAD must reject tampering");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn file_is_not_plaintext() {
        let path = temp_path("opaque");
        save_encrypted(MNEMONIC, "pass", &path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        // The mnemonic words must not appear anywhere in the file.
        let haystack = String::from_utf8_lossy(&bytes);
        assert!(!haystack.contains("current"), "mnemonic leaked into file");
        assert!(!haystack.contains("buffalo"), "mnemonic leaked into file");
        std::fs::remove_file(&path).unwrap();
    }
}
