//! protocol — the only structured messages that cross the tunnel.
//!
//! Negotiation (price, scope, deadline) is just chat between two LLMs, so
//! it is NOT modeled here. The protocol gets a formal shape only where
//! money is involved: ask for an address, announce a broadcast. Two
//! verbs. Everything else rides as `Chat`.
//!
//! Wire framing is length-prefixed JSON (4-byte big-endian length + body)
//! so structured verbs and free-form chat can share one byte stream
//! without a delimiter collision.

use serde::{Deserialize, Serialize};

use crate::wallet::Wallet;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// "I want to pay you `sats`. Give me an address."
    AddrRequest { sats: u64 },
    /// "Pay this address." `index` doubles as the payment identifier and
    /// is RBF-stable (fee-bumps change the txid, not the address).
    AddrResponse { address: String, index: u32 },
    /// "I broadcast the payment." The receiver confirms on-chain; this is
    /// a fast-path hint, not the source of truth.
    Notify { txid: String, sats: u64 },
    /// Free-form coordination — the chat lane.
    Chat { text: String },
}

impl Message {
    /// Encode as a length-prefixed frame ready to write to the tunnel.
    pub fn encode(&self) -> Vec<u8> {
        let body = serde_json::to_vec(self).expect("Message serializes");
        let len = (body.len() as u32).to_be_bytes();
        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&len);
        frame.extend_from_slice(&body);
        frame
    }

    /// Decode one frame from the front of `buf`. Returns the message and
    /// how many bytes it consumed, or `None` if `buf` doesn't yet hold a
    /// full frame (caller should read more and retry).
    pub fn decode(buf: &[u8]) -> Option<(Message, usize)> {
        if buf.len() < 4 {
            return None;
        }
        let len = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
        let end = 4 + len;
        if buf.len() < end {
            return None;
        }
        let msg = serde_json::from_slice(&buf[4..end]).ok()?;
        Some((msg, end))
    }
}

/// The receive side of a payment. Answers `AddrRequest` with a fresh
/// address each time, advancing the derivation index so no address is
/// ever reused. In v1 the index counter lives in memory; step 5 moves it
/// into the signed ledger so it survives a restart.
pub struct Receiver<'a> {
    wallet: &'a Wallet,
    next_index: u32,
}

impl<'a> Receiver<'a> {
    pub fn new(wallet: &'a Wallet, start_index: u32) -> Self {
        Self { wallet, next_index: start_index }
    }

    /// Handle an inbound message. Returns a reply to send back, if any.
    pub fn handle(&mut self, msg: Message) -> Result<Option<Message>, crate::wallet::Error> {
        match msg {
            Message::AddrRequest { .. } => {
                let index = self.next_index;
                let address = self.wallet.address(index)?.to_string();
                self.next_index += 1;
                Ok(Some(Message::AddrResponse { address, index }))
            }
            // Notify and Chat need no protocol reply; the chain (step 2)
            // is what actually confirms a Notify.
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet as CmWallet;

    const M: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn frame_round_trip() {
        let msgs = vec![
            Message::AddrRequest { sats: 50_000 },
            Message::AddrResponse { address: "tb1p…".into(), index: 7 },
            Message::Notify { txid: "abcd".into(), sats: 50_000 },
            Message::Chat { text: "ship it".into() },
        ];
        for m in msgs {
            let frame = m.encode();
            let (decoded, consumed) = Message::decode(&frame).unwrap();
            assert_eq!(decoded, m);
            assert_eq!(consumed, frame.len());
        }
    }

    #[test]
    fn two_frames_in_one_buffer() {
        // chat + addr_request back to back in one byte stream
        let a = Message::Chat { text: "hi".into() };
        let b = Message::AddrRequest { sats: 1000 };
        let mut buf = a.encode();
        buf.extend(b.encode());

        let (m1, n1) = Message::decode(&buf).unwrap();
        assert_eq!(m1, a);
        let (m2, _) = Message::decode(&buf[n1..]).unwrap();
        assert_eq!(m2, b);
    }

    #[test]
    fn partial_frame_returns_none() {
        let frame = Message::AddrRequest { sats: 1 }.encode();
        assert!(Message::decode(&frame[..frame.len() - 1]).is_none());
    }

    #[test]
    fn receiver_answers_with_rotating_addresses() {
        let w = CmWallet::from_mnemonic(M).unwrap();
        let mut rx = Receiver::new(&w, 0);

        let r0 = rx.handle(Message::AddrRequest { sats: 100 }).unwrap().unwrap();
        let r1 = rx.handle(Message::AddrRequest { sats: 200 }).unwrap().unwrap();

        match (r0, r1) {
            (
                Message::AddrResponse { address: a0, index: i0 },
                Message::AddrResponse { address: a1, index: i1 },
            ) => {
                assert_eq!(i0, 0);
                assert_eq!(i1, 1);
                assert_ne!(a0, a1, "each request must get a fresh address");
                assert_eq!(a0, w.address(0).unwrap().to_string());
                assert_eq!(a1, w.address(1).unwrap().to_string());
            }
            other => panic!("expected two AddrResponses, got {other:?}"),
        }
    }

    #[test]
    fn notify_and_chat_get_no_reply() {
        let w = CmWallet::from_mnemonic(M).unwrap();
        let mut rx = Receiver::new(&w, 0);
        assert!(rx.handle(Message::Notify { txid: "x".into(), sats: 1 }).unwrap().is_none());
        assert!(rx.handle(Message::Chat { text: "x".into() }).unwrap().is_none());
    }
}
