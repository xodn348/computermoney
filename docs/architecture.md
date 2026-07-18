---
title: Architecture
nav_order: 2
---

# Architecture: basic principles and mechanism

This page explains how `cm` (the `computermoney` binary) actually works: the principles it is built on, and the mechanism of each of its three layers. It is the "why and how" companion to two more detailed pages: the [reference](reference.md) lists every module, data structure, function, CLI command, and environment variable, and the [payment flow](payment-flow.md) walks a single payment function by function in order. To drive the whole thing from an agent in plain language, see [MCP usage](mcp-usage.md).

## 1. Principles

`cm` is a self-custodial Bitcoin L1 (mainnet) wallet that each AI agent runs itself. Five ideas hold the whole design together.

- **Self-custodial.** Each agent holds its own BIP-39 mnemonic and nothing else. At rest the seed is sealed with a passphrase: Argon2id (memory-hard) stretches the passphrase to a 32-byte key and ChaCha20-Poly1305 encrypts the mnemonic under it, so a stolen `seed.enc` resists offline brute-force and a wrong passphrase fails the AEAD tag rather than returning garbage (`storage::save_encrypted` / `load_encrypted`). There is no server holding keys.
- **Agent-run, no processor, no account.** There is no Stripe, Coinbase, or PayPal in the path, and no signup or invoice. An agent asks for a resource or names a payee and the payment happens underneath it. `cm mcp` exposes the wallet to an agent as plain-language tools, and the seed never crosses that tool boundary.
- **Key is identity.** One mnemonic is the agent's entire identity. Every other key is a deterministic branch of it (see the derivation table below), so the same secret secures the money, the tunnel, and the discovery card.
- **Chain is truth.** No peer's message is ever trusted to mean money moved. The receiver credits the real on-chain output and lets confirmations advance it. A payment notice over the tunnel is only a hint that makes the receiver look at the chain sooner.
- **Addressed by a cryptographic key.** A peer is found and paid by its card key (a 32-byte ed25519 public key), with no central directory. A payee that publishes a static silent-payment code can be paid while fully offline.

### Key is identity: one seed, every branch

`wallet.rs` turns the one mnemonic into a master `Xpriv` and derives each role from a fixed path. `{coin}` is 0 on mainnet, 1 on any test network.

| Role | Path | Used for |
|---|---|---|
| Receive (external) | `m/86'/{coin}'/0'/0/{i}` | BIP-86 Taproot receive address per index |
| Change (internal) | `m/86'/{coin}'/0'/1/{i}` | change outputs |
| Ledger signing | `m/86'/{coin}'/0'/2/0` | signs each append-only ledger entry |
| Network identity | `m/86'/{coin}'/0'/3/0` | the 32-byte seed behind BOTH the tunnel key and the card key |
| SP scan | `m/352'/{coin}'/0'/1'/0` | detects incoming silent payments (hot) |
| SP spend | `m/352'/{coin}'/0'/0'/0` | spends a received silent payment (can stay cold) |

The network-identity branch (3) is the interesting one: those same 32 bytes serve two network roles. `tunnel::identity` clamps them into an X25519 WireGuard static secret, and `discover::card_pubkey_bytes` feeds them to an ed25519 signing key. ed25519 hashes its seed before use, so the card scalar and the tunnel scalar are unrelated even though one secret backs both. A signature can never be replayed as a Diffie-Hellman key or vice versa.

Two distinct public handles fall out of this, and it is worth keeping them straight:

- **Card key**: the ed25519 public key (64 hex), the resolve-and-pay handle you share. This is what `cm id` prints and what a peer looks up on the DHT. "A peer is its card key."
- **WireGuard key** (`wallet::id_hex`): the X25519 public key (64 hex), the tunnel identity. It travels inside the card as the `wg` field, doubles as the direct-dial handle (`wg-key@host:port`), and its first 8 hex chars name the wallet's on-disk state directory.

## The three layers

```
   Agent A (payer)                                     Agent B (payee)
   one seed -> all keys                                one seed -> all keys
        |                                                    |
        |  (1) DISCOVER  ---- BitTorrent Mainline DHT --->   |  publishes a signed card
        |      resolve B's card key (ed25519)                |  { wg, ep[], sp, at }
        |      -> B's sp code + WG endpoint                  |  under its card key
        |                                                    |
        |  (2) TALK      <--- WireGuard tunnel (UDP) --->    |  answers AddrRequest with
        |      messages only, never coins, LAN/localhost     |  a fresh address
        |      (the offline path skips this layer)           |
        |                                                    |
        |  (3) SETTLE    ---- Bitcoin L1 (one Taproot tx) -> |  scans / reconciles the chain
        v      the chain is the source of truth              v  (the only proof of receipt)
   +----------------------- Bitcoin network ------------------------+
   |   0 conf = Pending   |   1-2 conf = Soft   |   3+ conf = Final |
   +---------------------------------------------------------------+
```

Each layer does exactly one job. Discovery finds a peer, the tunnel carries coordination messages, and Bitcoin L1 moves the actual value. The coordination/settlement split is enforced in code: the payment protocol in `net.rs` sits behind a `Wire` trait and does not know which transport carries its bytes, which is why the tests can swap the WireGuard tunnel for a plain TCP stand-in and the payment logic does not move.

## Layer 1: Discover (BitTorrent Mainline DHT)

The problem is finding a peer with no server to ask. `cm` solves it with BEP-44 mutable items on the BitTorrent Mainline DHT, the most widely deployed serverless system there is (roughly 10 million always-on nodes). Grounded in `discover.rs` and `protocol.rs`.

**What a card key is.** An agent's discovery identity is a 32-byte ed25519 public key derived from the network-identity seed (`discover::card_pubkey_bytes`, printed as 64 hex by `card_pubkey_hex`). In BEP-44 the storage address of a mutable item is derived from an ed25519 public key, and only the holder of the matching secret can write to it. So the card key is simultaneously the peer's name, its lookup address, and its write authorization. There is nothing else to trust.

**What the signed card contains.** The `Card` struct is deliberately tiny (BEP-44 caps a mutable value at 1000 bytes, checked as `MAX_CARD_BYTES` before publish):

- `wg`: the 64-hex X25519 WireGuard public key, the tunnel identity, always present.
- `ep`: an optional list of endpoints (`"host:port"`, or `"[v6]:port"`), the addresses a payer dials. There may be several (a v4 and a v6) or none. A dial-out-only buyer publishes no endpoint, since it never accepts inbound sessions. Publishing an endpoint exposes that IP to every holder of the card key, so operators publish a hop/VPS address or nothing.
- `sp`: the optional silent-payment code (`sp1…` on mainnet, `tsp1…` elsewhere). A payer who resolves this can pay it on-chain while the agent is entirely offline, no tunnel. It is optional so pre-silent-payment (v1) cards still parse.
- `at`: publication time in unix seconds, which doubles as the record's monotonic sequence number so a later publish supersedes an earlier one.

Notably the card carries only what discovery needs (where and how to reach the agent, and the offline pay-to code). It says nothing about balances or history.

**Publish.** `discover::publish` serializes the card to JSON, checks the size cap, signs it with the ed25519 secret, and puts it as a `MutableItem` under the salt `b"cm"` with `seq = card.at`. The salt namespaces cm's records so the same key used by another application resolves to a different target. This is a blocking call on the DHT client's own thread (cm is deliberately synchronous, with no async runtime).

**Resolve.** `discover::resolve` takes a peer's card public key and calls `get_mutable_most_recent` under the same salt, retrying up to `RESOLVE_ATTEMPTS` (5) times because a single cold lookup can miss a record that has not yet propagated to the nodes this client happens to query. Signature verification is enforced by the DHT layer: a record that does not verify against the given card key is never returned, so a resolver cannot be handed a forged card.

Reference: [BEP 44 (DHT mutable storage)](https://www.bittorrent.org/beps/bep_0044.html).

## Layer 2: Talk (WireGuard)

When both agents are online and want a live exchange, `cm` opens a real WireGuard tunnel between them. It carries coordination messages only, never coins. Grounded in `tunnel.rs`, `net.rs`, and `serve.rs`.

**Keyed by the same seed.** `tunnel::identity` builds the WireGuard X25519 static secret directly from the wallet's network-identity branch (3), the same 32 bytes described above. The tunnel uses boringtun, which gives the genuine WireGuard protocol: the Noise_IK handshake and ChaCha20-Poly1305 transport. There is no separate key management; the wallet that holds the money is the wallet that authenticates the channel.

**Messages only, never coins.** The only things that cross the tunnel are the four variants of `protocol::Message`:

- `AddrRequest { sats }`: "I want to pay you this much, give me an address."
- `AddrResponse { address, index }`: a fresh receive address plus its derivation index (the index doubles as an RBF-stable payment identifier).
- `Notify { txid, sats }`: "I broadcast the payment." This is an untrusted hint, not proof.
- `Chat { text }`: free-form coordination. Negotiation over price or scope is just chat between two LLMs, so only the money-touching verbs are given a formal shape.

Each message is length-prefixed JSON. Because WireGuard tunnels IP, `cm` wraps each frame in a minimal IPv4 packet (`wrap_ip`, using an experimental protocol number since there is no real L4 inside), then encrypts it. A test in `tunnel.rs` confirms the plaintext JSON never appears in the encrypted datagram.

**LAN/localhost, and the offline path skips it.** The tunnel runs over UDP and is meant for a LAN or localhost exchange, not an open-internet service. It is entirely optional: a payer who has resolved a card's `sp` code can settle on-chain with no handshake at all, and the receiver books the money later by scanning the chain (Layer 3). That offline path is the common case; the tunnel is only for a live, interactive exchange.

**The receiver never trusts the notice.** In `net::run_receiver`, an `AddrRequest` gets a fresh address (the ledger records an `AddressIssued`), but a `Notify` is treated as hostile input. The receiver does not credit the claimed amount. Instead it queries the chain (`chain::deposits_to`) to confirm that this txid actually pays the address it issued this session, and books the real on-chain amount via `record_received`. If the transaction is not visible yet, it records nothing and lets the daemon's chain-watch book it once it lands. `net::run_payer` mirrors this: it gates the amount against policy before contacting the peer, asks for an address, checks that address against the blocklist, settles on-chain, records the send, and only then notifies.

**The resident daemon.** `serve.rs` is the seller's body: one single-threaded loop that never sleeps and does three duties. REPUBLISH keeps the DHT card fresh (every 45 minutes, so it never falls out of the DHT). WATCH polls the chain for deposits with no live session and advances pending payments, plus scans for silent-payment income (every 60 seconds). ACCEPT answers any buyer's handshake using `FramedTunnel::accept_any`, which learns the initiator's static key from the handshake itself rather than pinning one expected peer in advance. The loop holds an exclusive directory lock for its whole life, because the ledger is a single-writer file, and its log lines are the operator's only UI.

Reference: [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf).

## Layer 3: Settle (Bitcoin L1)

Value moves as exactly one Taproot transaction per payment, over the payer's own link to the Bitcoin network (not the tunnel). Grounded in `chain.rs`, `sp.rs`, and `scan.rs`.

**Building one transaction.** `chain.rs` is where bdk and esplora live. `chain::build_signed` syncs the descriptor's UTXOs, builds a P2TR payment (bdk does branch-and-bound coin selection and change), fetches a recommended feerate clamped into a sane range, enforces the policy fee cap at the last moment the fee is known, and signs. Broadcasting is a separate step (`chain::broadcast`). The send path in `pay.rs` uses that split deliberately: it builds and signs, persists the raw signed tx as a sidecar and appends a durable Pending `Sent` entry, and only then broadcasts. If the process dies in that gap, the payment is still on the work queue and the sidecar lets reconcile rebroadcast it. Every mainnet build first passes a fail-closed guard (`ensure_mainnet_capped`) that refuses to sign without a spend cap.

**Silent Payments (BIP-352): paid while offline.** One published static code lets a payer derive a fresh one-time Taproot output for the receiver, so no address is reused and the receiver need not be online. `sp.rs` is the pure cryptographic core, verified against the official BIP-352 send and receive test vectors.

- *Sender* (`sp::send_address`): sum the secret keys of the chosen transaction inputs into `a_sum`, compute the BIP-352 input hash from the smallest outpoint, derive the shared secret `ecdh = input_hash * a_sum * B_scan`, and from it the one-time output key `P_0 = B_spend + t_0*G`. That key is used verbatim as the Taproot output key. Because a silent-payment address is fixed by the exact inputs that fund it, `chain::build_signed_to_sp` pins its input set before the recipient address even exists.
- *Receiver* (`scan.rs`): there is no address to watch, so the receiver reads the chain itself. `scan::scan_to_tip` walks blocks from a saved checkpoint to the tip, and for each transaction reconstructs the input public keys from esplora's prevout data (P2TR key-path keys lifted to even Y, P2WPKH keys taken verbatim), then runs the BIP-352 receive check (`sp::receive_check`) with the wallet's scan key: `ecdh = input_hash * b_scan * A_sum`, then derive candidate output keys `k = 0, 1, …` and match them against the transaction's outputs. Each match yields the tweak `t_k`, so the spend key is later recovered as `b_spend + t_k`. Matches above the dust floor are booked as Pending `SpReceived`. A checkpoint (`scan.json`) only advances after a fully successful pass, so an interrupted scan is retried rather than skipped.

**The confirmation ladder.** A booked receipt advances through a status ladder driven purely by confirmation count (`ledger::Status::from_confirmations`), where a confirmation count is `tip_height - block_height + 1`:

- **0 confirmations = Pending.** Seen but not yet mined. Not spendable.
- **1-2 confirmations = Soft.** Mined and acknowledged as a receipt, but not yet safe against a shallow reorg. Still not spendable.
- **3+ confirmations = Final.** The delivery gate. Only now does the money count toward spendable balance.

Spendability follows the ladder exactly. `ledger::balance` and `ledger::sp_balance` count a receive only when its effective status is Final, while a send is debited immediately (the money has left). A separate `Failed` status sits off the ladder: it is never inferred from a confirmation count, only set by reconcile when a Sent transaction is proven dead (its inputs are gone), and a Failed send is never debited because it never moved money.

Reference: [BIP-352 (Silent Payments)](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki).

## Also over HTTP 402

The same settlement rail powers a paid-data path: an agent can sell one body behind an HTTP 402 and another can buy it, with no signup, card, or account. Grounded in `paywall.rs` (seller) and `fetch.rs` (buyer).

**Seller.** `paywall::run` serves one fixed body for a fixed price on a bound TCP listener (single-threaded, one buyer at a time). A GET with no valid payment gets back HTTP 402 and a small JSON `Terms` body carrying the seller's static silent-payment code:

```
HTTP/1.1 402 Payment Required
{"cm402":1,"sats":800,"pay_to":"sp1…","network":"mainnet"}
```

The buyer pays that code on-chain and retries the GET with an `X-Payment: <txid>` header. The seller verifies the claim with `scan::tx_pays_me`, which reconstructs the transaction and runs the BIP-352 receive check against the seller's own scan key. If the transaction pays the seller at least the price, and the txid has not already been redeemed this session (a single-use set makes one txid buy at most once), the body is returned. The path is ignored: this endpoint sells exactly one thing. This lean cut is demo-grade on purpose (0-conf delivery, plain HTTP, a bare txid as proof).

**Buyer.** `fetch::fetch` GETs a URL and, on a 402, auto-pays within a caller-supplied cap. It first refuses anything that is not a cm 402 for the right network, then checks that `pay_to` is a silent-payment code for that network and that the quoted price is within `max_sats`. Only then does it apply the standing wallet policy (amount cap, daily window, blocklist), because the amount is only known once the 402 is read. It pays the code with `pay::sp_send`, then retries the GET with the txid as proof up to a few times to cover mempool propagation. The agent driving `fetch` never sees a key or an address: it asks for a resource, and the payment happens underneath.

## Where to go next

- [Payment flow](payment-flow.md): the same single payment, function by function, in the exact order the sender and receiver execute it.
- [Reference](reference.md): every module, data structure and variable, function, CLI command, and environment variable.
- [MCP usage](mcp-usage.md): the MCP tools that let an agent drive all of the above in plain language.

Licensed under the GNU AGPL v3.0, Copyright (C) 2026 Ebsilon, Inc.
