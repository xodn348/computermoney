//! wallet — seed to keys, nothing else.
//!
//! Pillar 1 (KEY IS IDENTITY): one BIP-39 mnemonic is the agent's whole
//! identity. This module turns that one secret into the keys every other
//! module needs. Milestone 1 only needs the Bitcoin receive key, so that
//! is all that lives here for now; the X25519 tunnel leaf and signing
//! paths land in later steps.
//!
//! Deliberately no `bdk` here. Address derivation is a pure key operation
//! with no chain state — the heavier UTXO/sync machinery belongs in
//! `chain/`. Keeping this module dependency-light keeps the highest-value,
//! highest-scrutiny code (the part that decides where money lands) small.

use std::str::FromStr;

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::{Keypair, XOnlyPublicKey};
use bitcoin::{Address, KnownHrp, Network};
use zeroize::{Zeroize, Zeroizing};

/// An agent wallet: one master key derived from one mnemonic.
pub struct Wallet {
    root: Xpriv,
    network: Network,
}

impl Wallet {
    /// Generate a fresh 12-word wallet on signet (the v1 test network).
    /// Returns the wallet and the mnemonic phrase to back up.
    pub fn generate() -> Result<(Self, String), Error> {
        let mnemonic = Mnemonic::generate(12)?;
        let phrase = mnemonic.to_string();
        let w = Self::from_mnemonic_on(Network::Signet, &phrase)?;
        Ok((w, phrase))
    }

    /// Restore a signet wallet from an existing mnemonic.
    pub fn from_mnemonic(phrase: &str) -> Result<Self, Error> {
        Self::from_mnemonic_on(Network::Signet, phrase)
    }

    /// Restore on an explicit network. Used by tests to check BIP-86
    /// against the spec's mainnet vectors.
    pub fn from_mnemonic_on(network: Network, phrase: &str) -> Result<Self, Error> {
        // `mnemonic` zeroizes its entropy on drop (bip39 "zeroize" feature).
        let mnemonic = Mnemonic::from_str(phrase.trim())?;
        let mut seed = mnemonic.to_seed(""); // no BIP-39 passphrase in v1
        let root = Xpriv::new_master(network, &seed)?;
        seed.zeroize(); // wipe the raw 64-byte seed once the master key is set
        // NOTE: `root` (the live master Xpriv) and the xprv embedded in the
        // bdk descriptor strings are NOT zeroized — bitcoin/bdk hold that key
        // material without Zeroize support. That is the current boundary.
        Ok(Self { root, network })
    }

    /// BIP-86 Taproot receive address at index `n`: m/86'/{coin}'/0'/0/n.
    /// Each payment uses a fresh index — the address doubles as the
    /// payment identifier and survives fee-bumps (RBF changes the txid,
    /// not the address).
    pub fn address(&self, index: u32) -> Result<Address, Error> {
        let secp = Secp256k1::new();
        let path = DerivationPath::from_str(&format!("m/86'/{}'/0'/0/{index}", self.coin_type()))?;
        let child = self.root.derive_priv(&secp, &path)?;
        let (xonly, _parity) = child.to_keypair(&secp).x_only_public_key();
        // None internal merkle root => BIP-86 key-path-only Taproot output.
        Ok(Address::p2tr(&secp, xonly, None, self.hrp()))
    }

    /// BIP-86 descriptors for bdk's chain layer. The wallet owns key
    /// derivation; `chain/` consumes these strings to sync UTXOs. Keeping
    /// the xprv inside the descriptor is fine in v1 (local, self-custody).
    /// External = receive (.../0/*), internal = change (.../1/*).
    pub fn descriptors(&self) -> (String, String) {
        let c = self.coin_type();
        let ext = format!("tr({}/86h/{c}h/0h/0/*)", self.root);
        let int = format!("tr({}/86h/{c}h/0h/1/*)", self.root);
        (ext, int)
    }

    /// The agent's ledger-signing identity key. Branch 2
    /// (m/86'/{coin}'/0'/2/0) is reserved for this and never produces a
    /// receive address (those use branches 0 and 1), so the signing key is
    /// never reused as a payment key.
    pub fn signing_keypair(&self) -> Result<Keypair, Error> {
        let secp = Secp256k1::new();
        let path = DerivationPath::from_str(&format!("m/86'/{}'/0'/2/0", self.coin_type()))?;
        let child = self.root.derive_priv(&secp, &path)?;
        Ok(child.to_keypair(&secp))
    }

    /// The x-only public key a counterparty uses to verify this agent's
    /// ledger signatures.
    pub fn signing_pubkey(&self) -> Result<XOnlyPublicKey, Error> {
        Ok(self.signing_keypair()?.x_only_public_key().0)
    }

    /// The agent's WireGuard static secret as raw 32 bytes, derived at
    /// branch 3 (m/86'/{coin}'/0'/3/0) — reserved for the tunnel identity,
    /// distinct from the receive (0/1) and ledger-signing (2) branches.
    /// Pillar 1: one mnemonic secures both the money and the tunnel. The
    /// caller builds an X25519 key from these bytes; they zeroize on drop.
    pub fn wg_secret_bytes(&self) -> Result<Zeroizing<[u8; 32]>, Error> {
        let secp = Secp256k1::new();
        let path = DerivationPath::from_str(&format!("m/86'/{}'/0'/3/0", self.coin_type()))?;
        let child = self.root.derive_priv(&secp, &path)?;
        Ok(Zeroizing::new(child.private_key.secret_bytes()))
    }

    fn coin_type(&self) -> u32 {
        // BIP-44 registered coin types: 0 = mainnet, 1 = all testnets.
        if self.network == Network::Bitcoin {
            0
        } else {
            1
        }
    }

    fn hrp(&self) -> KnownHrp {
        if self.network == Network::Bitcoin {
            KnownHrp::Mainnet
        } else {
            KnownHrp::Testnets
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Mnemonic(bip39::Error),
    Bip32(bitcoin::bip32::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Mnemonic(e) => write!(f, "mnemonic: {e}"),
            Error::Bip32(e) => write!(f, "bip32: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<bip39::Error> for Error {
    fn from(e: bip39::Error) -> Self {
        Error::Mnemonic(e)
    }
}

impl From<bitcoin::bip32::Error> for Error {
    fn from(e: bitcoin::bip32::Error) -> Self {
        Error::Bip32(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-86 official test vectors (the spec's own mnemonic + addresses).
    // Proves our derivation path, Taproot tweak, and bech32m encoding are
    // all correct against an external reference.
    const VECTOR_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn bip86_mainnet_vector_receive_0() {
        let w = Wallet::from_mnemonic_on(Network::Bitcoin, VECTOR_MNEMONIC).unwrap();
        assert_eq!(
            w.address(0).unwrap().to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
    }

    #[test]
    fn bip86_mainnet_vector_receive_1() {
        let w = Wallet::from_mnemonic_on(Network::Bitcoin, VECTOR_MNEMONIC).unwrap();
        assert_eq!(
            w.address(1).unwrap().to_string(),
            "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"
        );
    }

    #[test]
    fn signet_address_is_taproot_testnet_hrp() {
        let w = Wallet::from_mnemonic_on(Network::Signet, VECTOR_MNEMONIC).unwrap();
        let addr = w.address(0).unwrap().to_string();
        assert!(addr.starts_with("tb1p"), "expected signet Taproot, got {addr}");
    }

    #[test]
    fn round_trip_generate_then_restore() {
        let (w1, phrase) = Wallet::generate().unwrap();
        let w2 = Wallet::from_mnemonic(&phrase).unwrap();
        assert_eq!(w1.address(0).unwrap(), w2.address(0).unwrap());
    }
}
