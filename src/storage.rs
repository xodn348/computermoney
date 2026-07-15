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

/// Root of all agent state: `~/.config/computermoney/`. Each identity
/// (wallet) is one subdirectory named by the first 8 hex chars of its
/// identity pubkey (`cm id`), holding `mnemonic` or `seed.enc` plus
/// `ledger.jsonl`. A `default` marker file at the root names the identity
/// used when `CM_ID` is not set.
fn config_root() -> PathBuf {
    // CM_HOME (an absolute path) overrides the default root — lets tests and
    // demos run several agents on one machine without sharing state.
    if let Ok(home) = std::env::var("CM_HOME") {
        let home = home.trim();
        if !home.is_empty() {
            return PathBuf::from(home);
        }
    }
    let mut p = std::env::var("HOME").map(PathBuf::from).unwrap_or_default();
    p.push(".config");
    p.push("computermoney");
    p
}

/// Take an exclusive, non-blocking lock on `dir` by locking `dir/"lock"`. The
/// returned File *is* the lock — the caller must keep it alive; dropping it (or
/// the process exiting) releases it. On contention this fails immediately rather
/// than blocking, so a second cm process can never become a concurrent writer to
/// the same wallet. `try_lock` is stable since 1.89 (we are on 1.94).
pub fn lock_dir(dir: &Path) -> Result<std::fs::File, Box<dyn Error>> {
    std::fs::create_dir_all(dir)?;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(dir.join("lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(std::fs::TryLockError::WouldBlock) => {
            Err(format!("another cm process holds this wallet ({})", dir.display()).into())
        }
        Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
    }
}

/// The identities stored on this machine: 8-lowercase-hex subdirectory
/// names under the config root, sorted. Anything else there is ignored.
pub fn wallet_ids() -> Vec<String> {
    let mut ids: Vec<String> = std::fs::read_dir(config_root())
        .into_iter()
        .flatten()
        .flatten()
        .filter(|e| e.path().is_dir())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.len() == 8 && n.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')))
        .collect();
    ids.sort();
    ids
}

/// Choose the acting identity among `ids`: an explicit `CM_ID` prefix wins,
/// then the `default` marker, then a sole wallet. Several wallets with no
/// selector is an error that lists them — never a silent guess. Pure, so
/// the selection rules are unit-testable.
fn pick_identity(
    ids: &[String],
    cm_id: Option<&str>,
    default: Option<&str>,
) -> Result<String, Box<dyn Error>> {
    if let Some(want) = cm_id {
        let want = want.trim();
        let hits: Vec<&String> = ids
            .iter()
            .filter(|id| {
                if want.len() >= 8 { want.starts_with(id.as_str()) } else { id.starts_with(want) }
            })
            .collect();
        return match hits.as_slice() {
            [one] => Ok((*one).clone()),
            [] => Err(format!("CM_ID={want} matches no identity here (have: {})", ids.join(", ")).into()),
            _ => Err(format!(
                "CM_ID={want} is ambiguous (matches: {})",
                hits.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            )
            .into()),
        };
    }
    if let Some(d) = default {
        let d = d.trim();
        if ids.iter().any(|id| id == d) {
            return Ok(d.to_string());
        }
    }
    match ids {
        [one] => Ok(one.clone()),
        [] => Err("no wallet: run `cm init` (or `cm setup`) first".into()),
        _ => Err(format!(
            "several identities live here ({}); set CM_ID=<prefix> to pick one",
            ids.join(", ")
        )
        .into()),
    }
}

/// The directory this wallet's state lives in: `<root>/<id8>/`, derived
/// from the wallet itself so it never depends on how the wallet was found.
pub fn wallet_dir(wallet: &Wallet) -> Result<PathBuf, Box<dyn Error>> {
    let id = wallet.id_hex()?;
    Ok(config_root().join(&id[..8]))
}

/// Where this agent's append-only ledger lives: `ledger.jsonl` inside the
/// wallet's identity directory. Ledger entries are identity-signed and
/// `open_with_identity` refuses foreign signatures, so two identities must
/// never share a file — the directory layout enforces that.
pub fn ledger_path(wallet: &Wallet) -> Result<PathBuf, Box<dyn Error>> {
    Ok(wallet_dir(wallet)?.join("ledger.jsonl"))
}

fn default_marker_path() -> PathBuf {
    config_root().join("default")
}

/// Persist a freshly generated wallet into its identity directory: sealed
/// `seed.enc` when a passphrase is given, otherwise a plaintext `mnemonic`
/// (owner-only 0600; callers gate mainnet). The first wallet on a machine
/// becomes the `default` identity. Returns the identity directory.
pub fn save_new_wallet(
    wallet: &Wallet,
    phrase: &str,
    passphrase: Option<&str>,
) -> Result<PathBuf, Box<dyn Error>> {
    let dir = wallet_dir(wallet)?;
    std::fs::create_dir_all(&dir)?;
    match passphrase {
        Some(pass) => save_encrypted(phrase, pass, &dir.join("seed.enc"))?,
        None => {
            let path = dir.join("mnemonic");
            std::fs::write(&path, format!("{phrase}\n"))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
    }
    let marker = default_marker_path();
    if !marker.exists() {
        std::fs::write(&marker, format!("{}\n", &wallet.id_hex()?[..8]))?;
    }
    Ok(dir)
}

/// Resolve an env override or `~/.config/computermoney/<file>`.
pub(crate) fn config_path(env_key: &str, file: &str) -> PathBuf {
    if let Ok(p) = std::env::var(env_key) {
        return PathBuf::from(p);
    }
    config_root().join(file)
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

/// Load the acting wallet. `CM_MNEMONIC` (an explicit escape hatch) wins;
/// otherwise resolve the identity directory — `CM_ID` prefix, then the
/// `default` marker, then a sole wallet — and unlock its `seed.enc` (with
/// `CM_PASSPHRASE`) or read its plaintext `mnemonic` (refused on mainnet).
pub fn load_wallet() -> Result<Wallet, Box<dyn Error>> {
    if let Ok(phrase) = std::env::var("CM_MNEMONIC") {
        let phrase = Zeroizing::new(phrase); // wipe our copy on drop
        return Ok(Wallet::from_mnemonic(phrase.as_str())?);
    }
    let cm_id = std::env::var("CM_ID").ok();
    let marker = std::fs::read_to_string(default_marker_path()).ok();
    let id = pick_identity(&wallet_ids(), cm_id.as_deref(), marker.as_deref())?;
    let dir = config_root().join(&id);
    let seed = dir.join("seed.enc");
    let w = if seed.exists() {
        let pass = std::env::var("CM_PASSPHRASE")
            .map_err(|_| format!("identity {id} has an encrypted seed; set CM_PASSPHRASE to unlock"))?;
        let phrase = load_encrypted(&pass, &seed)?; // Zeroizing<String>
        Wallet::from_mnemonic(phrase.as_str())?
    } else {
        let mn = dir.join("mnemonic");
        if !mn.exists() {
            return Err(format!("identity {id} has no seed.enc or mnemonic file — recreate it with `cm init`").into());
        }
        // A bare key on disk is a test-network convenience, never a way to
        // hold real funds: on mainnet it is refused, not silently used.
        if network() == Network::Bitcoin {
            return Err("plaintext mnemonic file found, refused on mainnet — \
                        recreate the wallet with CM_PASSPHRASE set"
                .into());
        }
        let phrase = Zeroizing::new(std::fs::read_to_string(&mn)?);
        Wallet::from_mnemonic(phrase.as_str())?
    };
    // The identity key depends on the coin type, so a wallet stored under a
    // testnet-derived name resolves to a different id on mainnet (and vice
    // versa). Refuse the mismatch instead of scattering state across dirs.
    let actual = w.id_hex()?;
    if !actual.starts_with(&id) {
        return Err(format!(
            "identity {id} resolves to {} on {} — this wallet belongs to a different network",
            &actual[..8],
            network_label()
        )
        .into());
    }
    Ok(w)
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
    fn pick_identity_rules() {
        let ids: Vec<String> = vec!["11aa22bb".into(), "99ff00ee".into()];
        // Explicit CM_ID: a unique prefix, or the full 64-hex identity.
        assert_eq!(pick_identity(&ids, Some("99"), None).unwrap(), "99ff00ee");
        let full = format!("11aa22bb{}", "c".repeat(56));
        assert_eq!(pick_identity(&ids, Some(&full), None).unwrap(), "11aa22bb");
        assert!(pick_identity(&ids, Some("77"), None).is_err(), "no match");
        assert!(pick_identity(&ids, Some(""), None).is_err(), "ambiguous");
        // The default marker, as read from disk (newline included).
        assert_eq!(pick_identity(&ids, None, Some("99ff00ee\n")).unwrap(), "99ff00ee");
        // A stale marker falls through; a sole wallet then auto-picks.
        assert_eq!(pick_identity(&ids[..1], None, Some("99ff00ee\n")).unwrap(), "11aa22bb");
        assert_eq!(pick_identity(&ids[..1], None, None).unwrap(), "11aa22bb");
        // Several without a selector refuse; none at all refuses.
        assert!(pick_identity(&ids, None, None).is_err());
        assert!(pick_identity(&[], None, None).is_err());
    }

    #[test]
    fn lock_dir_is_exclusive() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("cm_lock_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let first = lock_dir(&dir).unwrap();
        assert!(lock_dir(&dir).is_err(), "a second lock on a held wallet must fail");
        drop(first); // releasing the lock lets the next acquirer in
        let third = lock_dir(&dir).unwrap();
        drop(third);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn wallet_dirs_differ_per_identity() {
        let a = Wallet::from_mnemonic(MNEMONIC).unwrap();
        let (b, _) = Wallet::generate().unwrap();
        let da = wallet_dir(&a).unwrap();
        assert_ne!(da, wallet_dir(&b).unwrap(), "two identities must never share a directory");
        assert_eq!(da, wallet_dir(&a).unwrap(), "same identity, same directory");
        assert_eq!(ledger_path(&a).unwrap(), da.join("ledger.jsonl"));
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
