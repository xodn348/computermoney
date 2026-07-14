//! discover — the DISCOVER layer: find a peer by key, with no central server.
//!
//! An agent publishes one signed business card to the BitTorrent Mainline
//! DHT (~10M always-on nodes, the most widely deployed serverless system
//! there is). The card is a BEP-44 *mutable* item: its address is derived
//! from an ed25519 public key, and only the holder of the matching secret
//! can write it. Readers resolve a peer's card by that public key alone.
//!
//! This is the entry point of the pipeline: resolve a peer's card key to
//! their current WireGuard endpoint, then the existing tunnel (TALK) and
//! Bitcoin L1 (SETTLE) take over. The card carries only what discovery
//! needs — the WG endpoint to open a tunnel to — and nothing about money.
//!
//! Why the deprecated sync calls: mainline marks its blocking `put_mutable`
//! / `get_mutable_most_recent` deprecated in favor of an async API, but that
//! path needs an async runtime. cm is deliberately sync (no tokio), so we
//! use the blocking calls on the crate's own DHT thread and silence the
//! deprecation locally.

use std::error::Error;

use mainline::{Dht, MutableItem, SigningKey};
use serde::{Deserialize, Serialize};

/// BEP-44 salt namespacing cm's records under one app on the shared DHT, so
/// the same key used elsewhere resolves to a different target than our card.
const SALT: &[u8] = b"cm";

/// BEP-44 caps a mutable value at 1000 bytes; the card fits with room.
const MAX_CARD_BYTES: usize = 1000;

/// An agent's signed business card: where to reach it. Deliberately tiny.
/// `wg` is `"<x25519-pub-hex>@<host:port>"` — the WireGuard identity and
/// endpoint a payer tunnels to. `at` is the publication time in unix
/// seconds, and doubles as the record's monotonic `seq` (a later publish
/// supersedes an earlier one).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Card {
    pub wg: String,
    pub at: u64,
}

/// The ed25519 card public key (32 bytes) for a card secret. This is the
/// agent's shareable discovery identity — the one thing a peer needs to
/// resolve the card.
pub fn card_pubkey_bytes(card_secret: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(card_secret).verifying_key().to_bytes()
}

/// The card public key as 64 lowercase hex chars, for `cm id` / sharing.
pub fn card_pubkey_hex(card_secret: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in card_pubkey_bytes(card_secret) {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parse a 64-hex-char card key into 32 bytes.
pub fn parse_card_key(hex: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err("card key must be 64 hex chars".into());
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "card key is not valid hex")?;
    }
    Ok(out)
}

/// Publish (sign + put) our card to the DHT under our ed25519 card key.
/// `seq = card.at`, so each republish supersedes the last. Blocking: returns
/// once the put has reached responsible nodes (or errors).
#[allow(deprecated)]
pub fn publish(card_secret: &[u8; 32], card: &Card) -> Result<(), Box<dyn Error>> {
    let value = serde_json::to_vec(card)?;
    if value.len() > MAX_CARD_BYTES {
        return Err(format!(
            "card is {} bytes, over the BEP-44 {MAX_CARD_BYTES}-byte limit",
            value.len()
        )
        .into());
    }
    let signer = SigningKey::from_bytes(card_secret);
    let item = MutableItem::new(signer, &value, card.at as i64, Some(SALT));
    let dht = Dht::client()?;
    dht.put_mutable(item, None)?;
    Ok(())
}

/// How many DHT lookups to try before giving up. A single cold lookup can
/// miss a record that has not yet reached the nodes this client happens to
/// query; retrying on the same (now warmer) client closes that gap. Each
/// attempt is a full network round trip, so no extra delay is needed.
const RESOLVE_ATTEMPTS: usize = 5;

/// Resolve a peer's card by their ed25519 card public key (32 bytes).
/// Returns `None` only if every attempt finds no record. Blocking.
/// Signature verification is enforced by the DHT layer: a record that does
/// not verify against `card_pubkey` is never returned.
#[allow(deprecated)]
pub fn resolve(card_pubkey: &[u8; 32]) -> Result<Option<Card>, Box<dyn Error>> {
    let dht = Dht::client()?;
    for _ in 0..RESOLVE_ATTEMPTS {
        if let Some(item) = dht.get_mutable_most_recent(card_pubkey, Some(SALT)) {
            let card: Card = serde_json::from_slice(item.value())?;
            return Ok(Some(card));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The BIP-86 vector seed's branch-4 bytes would need the wallet; here we
    // check the pure key/parse helpers with fixed bytes, no network.
    #[test]
    fn pubkey_is_stable_hex_and_round_trips_parse() {
        let secret = [7u8; 32];
        let hex = card_pubkey_hex(&secret);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));
        // hex of the pubkey parses back to the same 32 bytes.
        assert_eq!(parse_card_key(&hex).unwrap(), card_pubkey_bytes(&secret));
    }

    #[test]
    fn parse_card_key_rejects_bad_input() {
        assert!(parse_card_key("xyz").is_err()); // too short
        assert!(parse_card_key(&"g".repeat(64)).is_err()); // not hex
    }

    #[test]
    fn card_serializes_small() {
        let card = Card {
            wg: format!("{}@1.2.3.4:51820", "ab".repeat(32)),
            at: 1_760_000_000,
        };
        let bytes = serde_json::to_vec(&card).unwrap();
        assert!(bytes.len() < MAX_CARD_BYTES, "card must fit BEP-44 cap");
    }
}
