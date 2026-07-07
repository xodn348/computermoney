//! tunnel — a real WireGuard tunnel, keyed by the wallet seed.
//!
//! Pillar 1 (key is identity) taken to its conclusion: the same mnemonic
//! that derives the Bitcoin keys also derives this agent's WireGuard
//! X25519 static key (derivation branch 3). One secret secures both the
//! money and the channel it travels over.
//!
//! boringtun gives the real WireGuard protocol — the Noise_IK handshake
//! and ChaCha20-Poly1305 transport. WireGuard carries IP packets, so each
//! payment frame rides inside a minimal IPv4 packet; that is exactly what
//! would happen if `cm receive`'s TCP ran over a kernel WG interface. The
//! coordination/settlement split holds: nothing in the payment protocol
//! knows the tunnel is here.

use std::error::Error;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::ledger::Ledger;
use crate::net::{self, Wire};
use crate::protocol::{Message, Receiver};
use crate::wallet::Wallet;

const IPV4_HEADER: usize = 20;
const WG_OVERHEAD: usize = 64; // type + counter + poly1305 tag headroom
// Must outlast the gap between AddrResponse and Notify, which spans the
// payer's on-chain broadcast (wallet sync + build + broadcast).
const RECV_TIMEOUT: Duration = Duration::from_secs(120);

/// This agent's WireGuard static identity (secret + public), from the seed.
pub fn identity(wallet: &Wallet) -> Result<(StaticSecret, PublicKey), Box<dyn Error>> {
    let secret = StaticSecret::from(*wallet.wg_secret_bytes()?);
    let public = PublicKey::from(&secret);
    Ok((secret, public))
}

/// Parse a peer's 64-hex-char (32-byte) WireGuard public key.
pub fn parse_public_key(hex: &str) -> Result<PublicKey, Box<dyn Error>> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err("WireGuard public key must be 64 hex chars (32 bytes)".into());
    }
    let mut bytes = [0u8; 32];
    for (i, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| "public key is not valid hex")?;
    }
    Ok(PublicKey::from(bytes))
}

// --- WireGuard crypto core: a boringtun tunnel plus IP framing ------------

/// What an inbound datagram turned into after decryption.
enum Step {
    /// Bytes to send back to the peer (handshake response / keepalive).
    SendBack(Vec<u8>),
    /// A decrypted application frame.
    Frame(Vec<u8>),
    /// Nothing actionable (a keepalive was consumed).
    Nothing,
}

/// The transport-agnostic crypto half. `FramedTunnel` drives it over UDP.
struct WgCore {
    tun: Tunn,
}

impl WgCore {
    fn new(secret: StaticSecret, peer: PublicKey) -> Self {
        // One tunnel per process in v1, so a fixed index is fine.
        Self { tun: Tunn::new(secret, peer, None, None, 0, None) }
    }

    /// Initiator: produce the first handshake packet to send to the peer.
    fn handshake_init(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut dst = vec![0u8; 256];
        match self.tun.format_handshake_initiation(&mut dst, false) {
            TunnResult::WriteToNetwork(out) => Ok(out.to_vec()),
            TunnResult::Err(e) => Err(format!("handshake init: {e:?}").into()),
            _ => Err("unexpected handshake-init result".into()),
        }
    }

    /// Feed one received datagram to the tunnel.
    fn process(&mut self, datagram: &[u8]) -> Result<Step, Box<dyn Error>> {
        let mut dst = vec![0u8; datagram.len() + WG_OVERHEAD];
        match self.tun.decapsulate(None, datagram, &mut dst) {
            TunnResult::WriteToNetwork(out) => Ok(Step::SendBack(out.to_vec())),
            TunnResult::WriteToTunnelV4(pkt, _) => Ok(Step::Frame(unwrap_ip(pkt)?)),
            TunnResult::WriteToTunnelV6(pkt, _) => Ok(Step::Frame(unwrap_ip(pkt)?)),
            TunnResult::Done => Ok(Step::Nothing),
            TunnResult::Err(e) => Err(format!("decapsulate: {e:?}").into()),
        }
    }

    /// Encrypt one frame into a datagram. Requires an established session.
    fn seal(&mut self, frame: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        let ip = wrap_ip(frame);
        let mut dst = vec![0u8; ip.len() + WG_OVERHEAD];
        match self.tun.encapsulate(&ip, &mut dst) {
            TunnResult::WriteToNetwork(out) => Ok(out.to_vec()),
            TunnResult::Err(e) => Err(format!("encapsulate: {e:?}").into()),
            _ => Err("tunnel has no session yet".into()),
        }
    }
}

/// Wrap an application frame as a minimal IPv4 packet so WireGuard, which
/// tunnels IP, will carry it. The total-length field must be exact —
/// boringtun truncates the decrypted packet to it, stripping WG padding.
fn wrap_ip(payload: &[u8]) -> Vec<u8> {
    let total = (IPV4_HEADER + payload.len()) as u16;
    let mut pkt = vec![0u8; IPV4_HEADER + payload.len()];
    pkt[0] = 0x45; // IPv4, header length 5 words
    pkt[2..4].copy_from_slice(&total.to_be_bytes());
    pkt[8] = 64; // TTL
    pkt[9] = 253; // RFC 3692 experimental protocol — no real L4 inside
    pkt[IPV4_HEADER..].copy_from_slice(payload);
    pkt
}

fn unwrap_ip(pkt: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    if pkt.len() < IPV4_HEADER {
        return Err("tunneled packet shorter than its IP header".into());
    }
    Ok(pkt[IPV4_HEADER..].to_vec())
}

// --- UDP transport --------------------------------------------------------

/// A WireGuard tunnel running over a UDP socket, carrying payment frames.
/// One peer per tunnel; `connect` is the initiator, `accept` the responder.
pub struct FramedTunnel {
    core: WgCore,
    sock: UdpSocket,
    peer: SocketAddr,
}

impl FramedTunnel {
    /// Initiator: open a tunnel to `peer` (its WG public key) and complete
    /// the handshake.
    pub fn connect(
        sock: UdpSocket,
        peer: SocketAddr,
        secret: StaticSecret,
        peer_pub: PublicKey,
    ) -> Result<Self, Box<dyn Error>> {
        sock.set_read_timeout(Some(RECV_TIMEOUT))?;
        let mut core = WgCore::new(secret, peer_pub);
        let init = core.handshake_init()?;
        sock.send_to(&init, peer)?;
        let mut t = Self { core, sock, peer };

        // Expect the handshake response, then send the keepalive it yields.
        let mut buf = [0u8; 2048];
        let (n, _from) = t.sock.recv_from(&mut buf)?;
        match t.core.process(&buf[..n])? {
            Step::SendBack(keepalive) => {
                t.sock.send_to(&keepalive, t.peer)?;
            }
            _ => return Err("handshake: expected a response".into()),
        }
        Ok(t)
    }

    /// Responder: wait for an inbound handshake, answer it, and bind to the
    /// peer that initiated.
    pub fn accept(
        sock: UdpSocket,
        secret: StaticSecret,
        peer_pub: PublicKey,
    ) -> Result<Self, Box<dyn Error>> {
        sock.set_read_timeout(Some(RECV_TIMEOUT))?;
        let mut core = WgCore::new(secret, peer_pub);
        let mut buf = [0u8; 2048];

        // 1. handshake initiation -> response. The socket is open to the
        // network, so datagrams that fail authentication (another WireGuard
        // stack's traffic, scans) are dropped like real WireGuard drops
        // them — only OUR peer's initiation ends the wait.
        let (resp, from) = loop {
            let (n, from) = sock.recv_from(&mut buf)?;
            match core.process(&buf[..n]) {
                Ok(Step::SendBack(resp)) => break (resp, from),
                Ok(_) => {}
                Err(e) => eprintln!("[wg] dropped an unauthenticated datagram ({e})"),
            }
        };
        sock.send_to(&resp, from)?;
        let mut t = Self { core, sock, peer: from };

        // 2. keepalive completes the session (junk dropped the same way)
        loop {
            let (n, _from) = t.sock.recv_from(&mut buf)?;
            match t.core.process(&buf[..n]) {
                Ok(_) => break,
                Err(e) => eprintln!("[wg] dropped an unauthenticated datagram ({e})"),
            }
        }
        Ok(t)
    }
}

impl Wire for FramedTunnel {
    /// Encrypt and send one message to the peer.
    fn send(&mut self, msg: &Message) -> Result<(), Box<dyn Error>> {
        let datagram = self.core.seal(&msg.encode())?;
        self.sock.send_to(&datagram, self.peer)?;
        Ok(())
    }

    /// Block until the next application message arrives, transparently
    /// answering handshake/keepalive traffic in between. Returns `None` if
    /// the socket goes idle (read timeout) — the tunnel's "peer is gone".
    fn recv(&mut self) -> Result<Option<Message>, Box<dyn Error>> {
        let mut buf = [0u8; 2048];
        loop {
            let (n, _from) = match self.sock.recv_from(&mut buf) {
                Ok(v) => v,
                Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            };
            // A datagram that fails authentication must not kill the
            // session — drop it and keep serving, exactly as WireGuard
            // does. (Stray WG traffic on the port is a fact of life.)
            let step = match self.core.process(&buf[..n]) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[wg] dropped an unauthenticated datagram ({e})");
                    continue;
                }
            };
            match step {
                Step::Frame(frame) => {
                    let (msg, _consumed) = Message::decode(&frame)
                        .ok_or("tunnel frame did not decode to a message")?;
                    return Ok(Some(msg));
                }
                Step::SendBack(b) => self.sock.send_to(&b, self.peer).map(|_| ())?,
                Step::Nothing => {}
            }
        }
    }
}

/// Run the receive protocol over a WireGuard tunnel. Waits for a peer to
/// open the tunnel (its public key must match `peer_pub_hex`), then serves
/// the payment exchange into the signed ledger.
pub fn serve(
    wallet: &Wallet,
    ledger_path: &Path,
    bind: &str,
    peer_pub_hex: &str,
) -> Result<(), Box<dyn Error>> {
    let (secret, _public) = identity(wallet)?;
    let peer_pub = parse_public_key(peer_pub_hex)?;
    let mut led = Ledger::open_with_identity(ledger_path, wallet.signing_keypair()?)?;
    let mut rx = Receiver::new(wallet, led.next_address_index());

    let sock = UdpSocket::bind(bind)?;
    eprintln!("cm receive: tunnel listening on {bind}");
    eprintln!("  ledger:  {}", ledger_path.display());
    eprintln!("  balance: {} sats final", led.balance());

    let mut tunnel = FramedTunnel::accept(sock, secret, peer_pub)?;
    eprintln!("[wg] tunnel established with peer");
    net::run_receiver(&mut tunnel, &mut rx, &mut led)
}

/// Pay a remote `cm receive` over a WireGuard tunnel.
pub fn pay(
    wallet: &Wallet,
    ledger_path: &Path,
    peer_addr: &str,
    peer_pub_hex: &str,
    sats: u64,
) -> Result<(), Box<dyn Error>> {
    let (secret, _public) = identity(wallet)?;
    let peer_pub = parse_public_key(peer_pub_hex)?;
    let peer: SocketAddr = peer_addr.parse().map_err(|_| "peer must be host:port")?;
    let mut led = Ledger::open_with_identity(ledger_path, wallet.signing_keypair()?)?;
    let (ext, int) = wallet.descriptors();

    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut tunnel = FramedTunnel::connect(sock, peer, secret, peer_pub)?;
    eprintln!("[wg] tunnel established");
    net::run_payer(&mut tunnel, &ext, &int, &mut led, sats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::Wallet;

    #[test]
    fn two_seed_identities_handshake_and_carry_a_frame() {
        let (a, _) = Wallet::generate().unwrap();
        let (b, _) = Wallet::generate().unwrap();
        let (a_sec, a_pub) = identity(&a).unwrap();
        let (b_sec, b_pub) = identity(&b).unwrap();

        let mut alice = WgCore::new(a_sec, b_pub);
        let mut bob = WgCore::new(b_sec, a_pub);

        // A real Noise_IK handshake, driven by passing buffers in-process.
        let init = alice.handshake_init().unwrap();
        let resp = match bob.process(&init).unwrap() {
            Step::SendBack(r) => r,
            _ => panic!("expected handshake response"),
        };
        let keepalive = match alice.process(&resp).unwrap() {
            Step::SendBack(k) => k,
            _ => panic!("expected keepalive"),
        };
        match bob.process(&keepalive).unwrap() {
            Step::Nothing => {}
            _ => panic!("expected handshake to complete"),
        }

        // A payment frame survives the tunnel, and the plaintext JSON does
        // not appear in the encrypted datagram.
        let msg = Message::AddrRequest { sats: 50_000 };
        let datagram = alice.seal(&msg.encode()).unwrap();
        let json = serde_json::to_vec(&msg).unwrap();
        assert!(
            !datagram.windows(json.len()).any(|w| w == json.as_slice()),
            "frame leaked plaintext into the encrypted datagram"
        );
        let frame = match bob.process(&datagram).unwrap() {
            Step::Frame(f) => f,
            _ => panic!("expected a decrypted frame"),
        };
        let (decoded, _) = Message::decode(&frame).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn udp_tunnel_round_trips_a_message() {
        let (a, _) = Wallet::generate().unwrap();
        let (b, _) = Wallet::generate().unwrap();
        let (a_sec, a_pub) = identity(&a).unwrap();
        let (b_sec, b_pub) = identity(&b).unwrap();

        let responder = UdpSocket::bind("127.0.0.1:0").unwrap();
        let responder_addr = responder.local_addr().unwrap();

        // Responder: accept the tunnel, echo one message back.
        let server = std::thread::spawn(move || {
            let mut t = FramedTunnel::accept(responder, b_sec, a_pub).unwrap();
            let got = t.recv().unwrap().unwrap();
            t.send(&got).unwrap();
        });

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut t = FramedTunnel::connect(client, responder_addr, a_sec, b_pub).unwrap();
        let msg = Message::Chat { text: "over wireguard".into() };
        t.send(&msg).unwrap();
        let echo = t.recv().unwrap().unwrap();
        assert_eq!(echo, msg);
        server.join().unwrap();
    }
}
