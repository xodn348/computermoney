//! policy — the gate every outgoing payment passes before it broadcasts.
//!
//! An autonomous wallet that can move money needs guardrails the agent
//! cannot talk its way around: a per-payment cap, a rolling daily cap, a
//! fee ceiling, and a blocklist (the OFAC-style "never pay this address").
//! The policy is data, loaded from `~/.config/computermoney/policy.json`
//! (override with `CM_POLICY`). An absent file means no restrictions — the
//! caller opts in by writing one.
//!
//! Checks are split by when their inputs are known: amount and daily
//! before contacting the peer (fail fast), address once the peer answers,
//! fee once the transaction is built (enforced inside `chain::send`).

use std::collections::HashSet;
use std::error::Error;
use std::fmt;

use serde::Deserialize;

use crate::storage;

/// The rolling window for the daily limit: the last 24 hours.
pub const DAILY_WINDOW_SECS: u64 = 86_400;

/// Limits and blocklist, all optional. Missing field = that limit is off.
#[derive(Debug, Default, Deserialize)]
pub struct Policy {
    /// Largest single payment, in satoshis.
    pub max_payment_sats: Option<u64>,
    /// Largest total spend in the last `DAILY_WINDOW_SECS`, in satoshis.
    pub daily_limit_sats: Option<u64>,
    /// Largest acceptable transaction fee, in satoshis.
    pub max_fee_sats: Option<u64>,
    /// Addresses this wallet must never pay.
    #[serde(default)]
    pub blocked_addresses: HashSet<String>,
}

/// A payment refused by policy. Typed so callers can react per reason.
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    PaymentTooLarge { sats: u64, cap: u64 },
    DailyLimitExceeded { attempted: u64, spent: u64, cap: u64 },
    FeeTooHigh { fee: u64, cap: u64 },
    AddressBlocked { address: String },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::PaymentTooLarge { sats, cap } => {
                write!(f, "payment of {sats} sats exceeds the per-payment cap of {cap} sats")
            }
            PolicyError::DailyLimitExceeded { attempted, spent, cap } => write!(
                f,
                "payment of {attempted} sats would push the last-24h spend to {} sats, over the daily cap of {cap} sats",
                spent + attempted
            ),
            PolicyError::FeeTooHigh { fee, cap } => {
                write!(f, "fee {fee} sats exceeds the cap of {cap} sats")
            }
            PolicyError::AddressBlocked { address } => {
                write!(f, "destination {address} is on the blocklist")
            }
        }
    }
}

impl Error for PolicyError {}

impl Policy {
    /// Load the policy file, or a permissive default if none exists.
    pub fn load() -> Result<Policy, Box<dyn Error>> {
        let path = storage::config_path("CM_POLICY", "policy.json");
        if !path.exists() {
            return Ok(Policy::default());
        }
        let text = std::fs::read_to_string(&path)?;
        Ok(serde_json::from_str(&text)?)
    }

    /// Amount gates, checked before the peer is contacted. `spent_recent`
    /// is the wallet's spend in the last `DAILY_WINDOW_SECS`.
    pub fn check_amount(&self, sats: u64, spent_recent: u64) -> Result<(), PolicyError> {
        if let Some(cap) = self.max_payment_sats {
            if sats > cap {
                return Err(PolicyError::PaymentTooLarge { sats, cap });
            }
        }
        if let Some(cap) = self.daily_limit_sats {
            if spent_recent + sats > cap {
                return Err(PolicyError::DailyLimitExceeded { attempted: sats, spent: spent_recent, cap });
            }
        }
        Ok(())
    }

    /// Blocklist gate, checked once the destination address is known.
    pub fn check_address(&self, to: &str) -> Result<(), PolicyError> {
        if self.blocked_addresses.contains(to) {
            return Err(PolicyError::AddressBlocked { address: to.to_string() });
        }
        Ok(())
    }

    /// Fee gate, checked once the transaction is built.
    pub fn check_fee(&self, fee: u64) -> Result<(), PolicyError> {
        if let Some(cap) = self.max_fee_sats {
            if fee > cap {
                return Err(PolicyError::FeeTooHigh { fee, cap });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            max_payment_sats: Some(100_000),
            daily_limit_sats: Some(250_000),
            max_fee_sats: Some(5_000),
            blocked_addresses: ["tb1pblocked".to_string()].into_iter().collect(),
        }
    }

    #[test]
    fn default_policy_allows_everything() {
        let p = Policy::default();
        assert!(p.check_amount(u64::MAX, u64::MAX / 2).is_ok());
        assert!(p.check_address("tb1panything").is_ok());
        assert!(p.check_fee(u64::MAX).is_ok());
    }

    #[test]
    fn per_payment_cap_is_enforced() {
        let p = policy();
        assert!(p.check_amount(100_000, 0).is_ok());
        assert_eq!(
            p.check_amount(100_001, 0),
            Err(PolicyError::PaymentTooLarge { sats: 100_001, cap: 100_000 })
        );
    }

    #[test]
    fn daily_limit_counts_recent_spend() {
        let p = policy();
        // 200k already spent today; another 50k is fine (250k cap), 60k is not.
        assert!(p.check_amount(50_000, 200_000).is_ok());
        assert_eq!(
            p.check_amount(60_000, 200_000),
            Err(PolicyError::DailyLimitExceeded { attempted: 60_000, spent: 200_000, cap: 250_000 })
        );
    }

    #[test]
    fn blocklist_rejects_listed_address() {
        let p = policy();
        assert!(p.check_address("tb1pclean").is_ok());
        assert_eq!(
            p.check_address("tb1pblocked"),
            Err(PolicyError::AddressBlocked { address: "tb1pblocked".to_string() })
        );
    }

    #[test]
    fn fee_cap_is_enforced() {
        let p = policy();
        assert!(p.check_fee(5_000).is_ok());
        assert_eq!(p.check_fee(5_001), Err(PolicyError::FeeTooHigh { fee: 5_001, cap: 5_000 }));
    }

    #[test]
    fn loads_from_json() {
        let json = r#"{"max_payment_sats":42,"blocked_addresses":["bad"]}"#;
        let p: Policy = serde_json::from_str(json).unwrap();
        assert_eq!(p.max_payment_sats, Some(42));
        assert_eq!(p.daily_limit_sats, None);
        assert!(p.check_address("bad").is_err());
    }
}
