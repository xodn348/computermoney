# Payment flow: what happens when you run `cm pay` / `cm receive`

This is the wire-level walkthrough of a single payment — what the **sender** and
**receiver** actually do, in order, the moment each command runs. The high-level
picture is in the [README](../README.md#how-a-payment-works-wireguard--cm--bitcoin-l1);
this is the function-by-function detail behind it.

Source of truth: [`src/tunnel.rs`](../src/tunnel.rs) (WireGuard transport) and
[`src/net.rs`](../src/net.rs) (the transport-agnostic payment protocol).

## The key idea: two handshakes, stacked

A payment rides two handshakes that are layered, never mixed:

1. **The WireGuard handshake** (Noise_IK, X25519) opens an *encrypted tunnel* between
   the two agents. This is the "secure pipe" — it authenticates *who* each side is by
   their X25519 public key (derivation branch 3, the `cm id` value) and encrypts
   everything sent afterward. This is the line `[wg] tunnel established`.
2. **The address handshake** (`AddrRequest` → `AddrResponse`) runs *inside* that tunnel.
   Its only job is to agree on *where the money goes*: the sender does not know a
   destination address until the receiver mints a fresh one and hands it back.

The WireGuard keys secure the channel; `AddrRequest`/`AddrResponse` are the first
conversation held over that now-encrypted channel. Only after **both** does any Bitcoin
move — and the coins move over the Bitcoin network, not the tunnel.

## Sequence

```
        cm pay (sender A)                          cm receive (receiver B)
 ══════════════════════════                 ══════════════════════════
 tunnel::pay                                 tunnel::serve
  │ seed → X25519 secret (branch 3)           │ seed → X25519 secret (branch 3)
  │ bind UDP 0.0.0.0:0                         │ bind UDP :51820  → "listening"  (waits)
  │                                           │
  │── 1. WireGuard handshake (Noise_IK) ──────────────────────────────────────
  │ FramedTunnel::connect                      │ FramedTunnel::accept
  │ handshake_init ──(msg1 initiation)───────▶ process initiation
  │ process       ◀──(msg2 response)────────── send back response
  │ ──keepalive──────────────────────────────▶ process → session ready
  │ ECDH session keys established              │  ⚠ wrong peer key → InvalidMac HERE
  │ "[wg] tunnel established"                  │  "[wg] tunnel established with peer"
  │                                           │
  │── from here every message is sealed inside the encrypted tunnel ──────────
 net::run_payer                              net::run_receiver  (recv loop)
  │ policy.check_amount   (spend gate)         │
  │                                           │
  │── 2. address handshake ───────────────────────────────────────────────────
  │ send AddrRequest{sats} ──(tunnel)────────▶ recv AddrRequest
  │                                           │   Receiver::handle → derive a fresh
  │                                           │   BIP-86 address (index++)
  │                                           │   ledger.append(AddressIssued, index)
  │ recv ◀──── AddrResponse{addr, index} ───── send AddrResponse
  │ policy.check_address(addr)  (blocklist)    │
  │                                           │
  │── 3. settle on Bitcoin L1 (NOT the tunnel — the open internet) ───────────
  │ chain::send: sync UTXOs (esplora)          │
  │   → build tx → recommended_feerate         │
  │   → Schnorr-sign → broadcast → txid        │
  │ ledger.append(Sent)   ← recorded BEFORE notifying (crash-safe)
  │                                           │
  │ send Notify{txid, sats} ──(tunnel)───────▶ recv Notify
  │ print txid + explorer link                 │   ledger.append(Received, Pending)
  │ done                                       │   ledger::reconcile → query confs on-chain
  │                                           │   advance status (0/1/3 = Pending/Soft/Final)
  │                                           │   keep listening; peer idle → exit
```

## What the sender does — `cm pay <peer-pubkey>@<host:port> <sats>`

`main.rs` → `tunnel::pay` → `net::run_payer`:

1. **Derive identity and connect.** Derive this agent's X25519 secret from the seed
   (branch 3), bind a UDP socket, and run the WireGuard *initiator* handshake to the
   peer's address, keyed to the peer's X25519 public key (`FramedTunnel::connect`). If
   that public key is wrong, decryption fails with `InvalidMac` — the **handshake**
   breaks, before any payment message is ever sent.
2. **Amount gate.** `policy.check_amount` runs before the first message, so an
   over-limit payment never even opens the conversation.
3. **Ask for an address.** Send `AddrRequest{sats}` over the tunnel; block until
   `AddrResponse{address, index}` comes back.
4. **Address gate.** `policy.check_address` checks the blocklist now that the
   destination is known.
5. **Settle on-chain.** `chain::send` syncs the wallet's UTXOs from esplora, builds the
   transaction, fetches the network's recommended feerate, Schnorr-signs, and broadcasts
   to the Bitcoin network. This is *not* carried by the tunnel — it is the sender's own
   link to Bitcoin (the open internet).
6. **Record, then notify.** Append a `Sent` entry to the signed ledger *before* sending
   `Notify{txid, sats}`, so a crash after broadcast still leaves the payment on the work
   queue. Print the txid and explorer link.

## What the receiver does — `cm receive <payer-pubkey> [bind]`

`main.rs` → `tunnel::serve` → `net::run_receiver`:

1. **Listen and handshake.** Bind a UDP socket and wait. Run the WireGuard *responder*
   handshake (`FramedTunnel::accept`), authenticating the initiator against the
   `<payer-pubkey>` you passed. The tunnel is up once the keepalive completes.
2. **Issue a fresh address.** On `AddrRequest{sats}`: `Receiver::handle` derives the next
   unused BIP-86 address, appends `AddressIssued{index}` to the ledger, and replies with
   `AddrResponse{address, index}`. A fresh address per payment means no address reuse, and
   the index later binds the payment to this issuance.
3. **Record the notify.** On `Notify{txid, sats}`: append a `Received` entry (status
   `Pending`).
4. **Reconcile against the chain.** Do not trust the `Notify` — `ledger::reconcile`
   queries the txid's confirmations on-chain and advances the ledger status
   (0/1/3 confs = Pending/Soft/Final). The chain, not the peer's message, is the source
   of truth for whether money arrived.
5. **Keep serving** until the peer goes idle (the socket read times out and `recv`
   returns `None`).

> **Honest gap.** Today `reconcile` confirms the txid is buried but does not yet verify
> that the transaction pays B's *issued address* for the *claimed amount*, so a lying
> `Notify` can record a phantom credit. Verifying the on-chain output inside `reconcile`
> is the top correctness fix (also noted in the README).

## Why `cm receive` must be running first

`cm pay` is the initiator and `cm receive` is the responder: the responder must already
be listening for the initiator to connect, and the receiver mints the destination address
*live* during the exchange — the sender has nowhere to send until it gets one. This is a
property of the **interactive coordination**, not of Bitcoin.

If you already know a static address out of band, `cm send <addr> <sats>` broadcasts
on-chain with no tunnel and no daemon — the receiver can be offline and check `cm balance`
later. That path skips address rotation, the `Notify` hint, and auto-reconcile.

## Framing detail

Each `Message` is `serde_json`-encoded (`Message::encode`), wrapped in a minimal IPv4
packet (WireGuard tunnels IP, so each frame rides inside one), encrypted by WireGuard's
ChaCha20-Poly1305 (`WgCore::seal` → `encapsulate`), and sent as a UDP datagram. On the
way in, `WgCore::process` decapsulates and `Message::decode` reassembles. The plaintext
JSON never appears in the encrypted datagram — verified by a test in `tunnel.rs`.

## The split, in one line

**WireGuard moves messages; Bitcoin L1 moves money; `cm` is the bridge.** The tunnel
carries `AddrRequest` / `AddrResponse` / `Notify` and nothing of value; the coins move
over the Bitcoin network and are confirmed by the chain. The payment protocol in `net.rs`
does not know which transport carries its bytes — swap the tunnel for the TCP stand-in in
the tests and the logic above does not move.
