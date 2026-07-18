---
title: Reference
nav_order: 4
---

# Reference

Technical reference for `computermoney` (binary `cm`), a self-custodial Bitcoin L1
(mainnet) wallet each AI agent runs itself. Pipeline: DISCOVER on the BitTorrent
Mainline DHT (a peer IS its card key, a 32-byte ed25519 public key) -> TALK over a
WireGuard tunnel (messages only, never coins) -> SETTLE on Bitcoin L1 (one Taproot
transaction per payment, Silent Payments BIP-352, confirmation ladder
0=Pending / 1-2=Soft / 3+=Final). It also sells and buys data over HTTP 402.
`cm mcp` exposes it to AI agents as plain-language tools; the seed never crosses
the tool boundary.

Everything below is derived from the source under `src/`. Line citations are
`file.rs:line`. See also [payment-flow.md](payment-flow.md) and
[mcp-usage.md](mcp-usage.md).

License AGPL v3, Copyright (C) 2026 Ebsilon, Inc. (per `LICENSE` and `README.md`;
note `Cargo.toml` still declares `license = "MIT"`, which is stale).

---

## 1. Module map

17 modules, all declared in `main.rs:6-21`.

| Module | Responsibility |
| --- | --- |
| `main.rs` | CLI entry point: parse `args`, dispatch each subcommand, print human output. |
| `wallet.rs` | Seed to keys. One BIP-39 mnemonic derives Taproot receive addrs (BIP-86), descriptors, the ledger-signing key, the BIP-352 SP scan/spend keys, and the WireGuard/card identity. No chain state. |
| `discover.rs` | DISCOVER layer. Publish/resolve a signed BEP-44 mutable `Card` on the Mainline DHT, keyed by the ed25519 card public key. |
| `sp.rs` | BIP-352 Silent Payments math and code encode/decode. Pure, I/O-free: derive a send address from inputs, scan a tx for payments to us, reconstruct the spend key. |
| `chain.rs` | Read/write Bitcoin via bdk + esplora. Balance, build+sign (plain / SP-send / SP-spending), broadcast, deposit history, confirmations, rebroadcast, feerate. |
| `ledger.rs` | Append-only signed log (the source of truth). Every economic fact is one Schnorr-signed JSON line; balance / pending / SP folds and `reconcile` read it. Also owns the signed-tx sidecar files. |
| `pay.rs` | The ordering-critical send path: build+sign -> write sidecar -> append durable Pending `Sent` -> broadcast. Shared by every send path (crash-safety in one place). |
| `policy.rs` | The gate every outgoing payment passes: per-payment / daily / fee caps, address blocklist, and the mainnet fail-closed guard. |
| `protocol.rs` | The only structured messages that cross the tunnel (length-prefixed JSON): `AddrRequest`/`AddrResponse`/`Notify`/`Chat`, plus the receive-side `Receiver`. |
| `net.rs` | Transport-agnostic payment protocol behind a `Wire` seam: `run_receiver` (issue addr, verify on-chain, record) and `run_payer` (ask, settle, notify). |
| `tunnel.rs` | Real WireGuard tunnel (boringtun Noise_IK) keyed by the wallet seed. `FramedTunnel` carries payment frames over UDP; implements `Wire`. |
| `serve.rs` | The resident seller daemon: one single-threaded loop that REPUBLISHes the card, WATCHes the chain, and ACCEPTs buyer tunnels. |
| `scan.rs` | BIP-352 Silent Payments chain scanner. Walk blocks from a checkpoint to tip via esplora JSON, reconstruct input keys, book SP income, track spends. |
| `paywall.rs` | Minimal HTTP 402 seller endpoint: serve one body for a fixed price, answer unpaid GETs with JSON `Terms`, verify a claimed txid pays us. |
| `fetch.rs` | Buyer-side auto-pay for HTTP 402: GET a URL, pay a cm 402's SP code within a cap, retry with the txid as proof. |
| `storage.rs` | Encrypted seed at rest (Argon2id + ChaCha20-Poly1305), config-dir layout, identity selection, wallet lock, and network/esplora/explorer config. |
| `mcp.rs` | Stdio JSON-RPC 2.0 MCP server exposing 11 plain-language tools to AI agents; reuses the exact CLI recipes. The seed is never a tool argument. |

---

## 2. Key data structures

### Wallet and identity

**`Wallet`** — `wallet.rs:24`. The agent's whole identity, one master key.

| Field | Type | Meaning |
| --- | --- | --- |
| `root` | `Xpriv` | BIP-32 master key derived from the mnemonic seed. |
| `network` | `Network` | Active Bitcoin network (drives coin type and HRP). |

Derivation branches off `m/86'/{coin}'/0'/…`: receive `0/n`, change `1/*`,
ledger-signing `2/0`, network identity (WireGuard + card) `3/0`. SP keys use a
separate `m/352'/{coin}'/0'/…` account (scan `1'/0`, spend `0'/0`).

### DHT card

**`discover::Card`** — `discover.rs:43`. The signed business card put to the DHT.
Serialized JSON must fit the BEP-44 1000-byte cap (`MAX_CARD_BYTES`, `discover.rs:30`).

| Field | Type | Meaning |
| --- | --- | --- |
| `wg` | `String` | 64-hex x25519 WireGuard public key (the tunnel identity), always present. |
| `ep` | `Vec<String>` | Optional dial endpoints, each `"host:port"` (or `"[v6]:port"`); empty for a dial-out-only buyer (skipped on the wire). |
| `sp` | `Option<String>` | The agent's silent-payment code (`sp1…`/`tsp1…`), when published. Optional so v1 cards still parse. |
| `at` | `u64` | Publication time (unix seconds); doubles as the record's monotonic `seq`. |

The card is addressed by the ed25519 card public key (`card_pubkey_bytes`,
`discover.rs:61`), derived from the wallet's branch-3 network-identity seed.

### Confirmation status

**`ledger::Status`** — `ledger.rs:37` (enum). The confirmation ladder.

| Variant | Meaning |
| --- | --- |
| `Pending` | 0 confirmations. |
| `Soft` | 1-2 confirmations (receipt ack). |
| `Final` | 3+ confirmations (delivery gate; spendable). |
| `Failed` | Off the ladder: set only by `reconcile` when a Sent tx is proven dead. A Failed send is never debited. |

`Status::from_confirmations` (`ledger.rs:48`) maps a count to Pending/Soft/Final;
it never returns `Failed`.

### Ledger entries

**`ledger::Entry`** — `ledger.rs:62` (enum, `#[serde(tag = "kind")]`). One economic
fact per line. `seq` is monotonic across all variants.

| Variant | Fields | Meaning |
| --- | --- | --- |
| `AddressIssued` | `seq, index` | A receive address at `index` was handed to a counterparty. |
| `Sent` | `seq, txid, sats, to, status, at` | We broadcast a payment; `at` is send time (feeds the daily fold), `to` records intent. |
| `Received` | `seq, txid, sats, index, status` | A payment to one of our issued addresses was observed. |
| `StatusUpdate` | `seq, txid, status` | `reconcile` advanced a payment's status (append-only; latest wins). |
| `SpReceived` | `seq, txid, vout, sats, tweak, status` | A silent-payment output paying us, found by scanning; `tweak` is the hex ECDH tweak `t_k` so the spend key `d = b_spend + t_k` is recoverable. |
| `SpSpent` | `seq, txid, vout` | An SP outpoint we held was spent (set-semantic, idempotent). |

Each on-disk line is a **`Record`** envelope (`ledger.rs:140`, private):
`{ entry: Entry, sig: String }`, where `sig` is a BIP-340 Schnorr signature by the
wallet's identity key over the SHA-256 of the entry's canonical JSON.

**`ledger::Ledger`** — `ledger.rs:146`.

| Field | Type | Meaning |
| --- | --- | --- |
| `path` | `PathBuf` | The `ledger.jsonl` file. |
| `entries` | `Vec<Entry>` | In-memory fold source, loaded (and verified) on open. |
| `identity` | `Option<Keypair>` | Signing key; `None` = unsigned ledger (tests). |

Supporting read types: **`Collection`** (`ledger.rs:97`: `index, txid, sats, sp`)
and **`SpUtxo`** (`ledger.rs:108`: `txid, vout, sats, tweak`).

### Spend policy

**`policy::Policy`** — `policy.rs:28`. Loaded from `policy.json`; every field optional
(missing = that limit is off).

| Field | Type | Meaning |
| --- | --- | --- |
| `max_payment_sats` | `Option<u64>` | Largest single payment. |
| `daily_limit_sats` | `Option<u64>` | Largest total spend in the last `DAILY_WINDOW_SECS` (86400, `policy.rs:24`). |
| `max_fee_sats` | `Option<u64>` | Largest acceptable transaction fee. |
| `blocked_addresses` | `HashSet<String>` | Addresses / payee handles this wallet must never pay. |

**`policy::PolicyError`** — `policy.rs:42` (enum): `PaymentTooLarge`,
`DailyLimitExceeded`, `FeeTooHigh`, `AddressBlocked`, `MainnetUncapped`,
`MainnetNoFeeCap`.

### HTTP 402 terms

**`paywall::Terms`** — `paywall.rs:35`. The 402 body (shared with `fetch`).

| Field | Type | Meaning |
| --- | --- | --- |
| `cm402` | `u8` | Version tag (always 1). |
| `sats` | `u64` | Price for one GET of the body. |
| `pay_to` | `String` | The seller's static SP code (`sp1…`/`tsp1…`). |
| `network` | `String` | Network label so the buyer can refuse cross-network. |

### Tunnel protocol messages

**`protocol::Message`** — `protocol.rs:18` (enum, `#[serde(tag = "type")]`).
Length-prefixed JSON (4-byte big-endian length + body).

| Variant | Fields | Meaning |
| --- | --- | --- |
| `AddrRequest` | `sats` | "I want to pay you `sats`. Give me an address." |
| `AddrResponse` | `address, index` | "Pay this address." `index` is the RBF-stable payment identifier. |
| `Notify` | `txid, sats` | "I broadcast the payment." A fast-path hint, not the source of truth. |
| `Chat` | `text` | Free-form coordination (the chat lane). |

**`protocol::Receiver`** — `protocol.rs:63`: `wallet: &Wallet`, `next_index: u32`.

### Silent-payment math types

- **`sp::SpInput`** (`sp.rs:32`): `outpoint: OutPoint`, `key: SecretKey` (a sender input, spend key even-Y normalized for Taproot).
- **`sp::TxInputs`** (`sp.rs:41`): `pubkeys: Vec<PublicKey>`, `smallest_outpoint: OutPoint` (the receiver's view of a tx's inputs).
- **`sp::SpFound`** (`sp.rs:49`): `vout: u32`, `sats: u64`, `tweak: [u8;32]` (a matched payment to us).

### Chain / scan / fetch result types

- **`chain::Balance`** (`chain.rs:26`): `confirmed: u64`, `pending: u64`.
- **`chain::Deposit`** (`chain.rs:457`): `txid: String`, `sats: u64`, `confirmations: u32`.
- **`chain::Rebroadcast`** (`chain.rs:498`, enum): `Accepted`, `Rejected(String)`.
- **`scan::ScanReport`** (`scan.rs:55`): `from_height: u32`, `to_height: u32`, `found: Vec<Found>`.
- **`scan::Found`** (`scan.rs:63`): `txid: String`, `vout: u32`, `sats: u64`.
- **`fetch::FetchOut`** (`fetch.rs:40`): `status: u16`, `body: String`, `paid: Option<(String, u64)>` (txid, sats).
- **`tunnel::FramedTunnel`** (`tunnel.rs:150`): `core: WgCore`, `sock: UdpSocket`, `peer: SocketAddr`.

### MCP request/response

No typed struct: `mcp.rs` builds JSON-RPC 2.0 frames as `serde_json::Value`.
Framing helpers (`mcp.rs:1064-1088`): `result_frame(id, result)`,
`error_frame(id, code, message)`, `tool_ok(id, text)`, `tool_err(id, text)`.
A `tools/call` result carries `{ "content": [{ "type": "text", "text": … }],
"isError": bool }`. Protocol version `2025-06-18` (`mcp.rs:47`).

---

## 3. Key functions

### wallet.rs — identity and key derivation

| Signature | Purpose | Loc |
| --- | --- | --- |
| `Wallet::generate() -> Result<(Self, String), Error>` | Fresh 12-word wallet on the active network; returns wallet + mnemonic. | `wallet.rs:32` |
| `Wallet::from_mnemonic(phrase: &str) -> Result<Self, Error>` | Restore from a mnemonic on the active network. | `wallet.rs:41` |
| `Wallet::address(&self, index: u32) -> Result<Address, Error>` | BIP-86 Taproot receive address at `index`. | `wallet.rs:63` |
| `Wallet::descriptors(&self) -> (String, String)` | (external, internal) BIP-86 descriptors for the bdk chain layer. | `wallet.rs:76` |
| `Wallet::signing_keypair(&self) -> Result<Keypair, Error>` | Ledger-signing identity key (branch `2/0`). | `wallet.rs:87` |
| `Wallet::sp_scan_keypair(&self) -> Result<Keypair, Error>` | BIP-352 SP scan key (`m/352'/…/1'/0`). | `wallet.rs:104` |
| `Wallet::sp_spend_keypair(&self) -> Result<Keypair, Error>` | BIP-352 SP spend key (`m/352'/…/0'/0`). | `wallet.rs:114` |
| `Wallet::sp_code(&self) -> Result<String, Error>` | This agent's static `sp1…`/`tsp1…` code. | `wallet.rs:123` |
| `Wallet::id_hex(&self) -> Result<String, Error>` | 64-hex WireGuard public key (`cm id`, wallet dir name). | `wallet.rs:132` |
| `Wallet::wg_secret_bytes(&self) -> Result<Zeroizing<[u8;32]>, Error>` | Branch-3 network-identity secret (WG + card seed). | `wallet.rs:152` |

### discover.rs — DHT card publish / resolve

| Signature | Purpose | Loc |
| --- | --- | --- |
| `card_pubkey_hex(card_secret: &[u8;32]) -> String` | Card public key as 64-hex (the shareable discovery identity). | `discover.rs:66` |
| `parse_card_key(hex: &str) -> Result<[u8;32], Box<dyn Error>>` | Parse a 64-hex card key to 32 bytes. | `discover.rs:76` |
| `publish(card_secret: &[u8;32], card: &Card) -> Result<(), Box<dyn Error>>` | Sign + put the card to the DHT (`seq = card.at`). | `discover.rs:93` |
| `resolve(card_pubkey: &[u8;32]) -> Result<Option<Card>, Box<dyn Error>>` | Resolve a peer's card by public key (retries `RESOLVE_ATTEMPTS`). | `discover.rs:120` |

### sp.rs — BIP-352 Silent Payments

| Signature | Purpose | Loc |
| --- | --- | --- |
| `encode(scan: &PublicKey, spend: &PublicKey, network: Network) -> String` | Encode an `sp1…`/`tsp1…` code. | `sp.rs:59` |
| `decode(code: &str) -> Result<(PublicKey, PublicKey, Network), Error>` | Decode a code to (scan, spend, network). | `sp.rs:77` |
| `send_address(inputs, scan, spend, network) -> Result<Address, Error>` | Derive the receiver's one-time Taproot output address from the sender's inputs. | `sp.rs:125` |
| `receive_check(inputs, outputs, scan_sk, spend_pk) -> Vec<SpFound>` | Scan one tx's outputs for payments to us; recover each tweak. Never errors. | `sp.rs:146` |
| `spend_keypair(spend_sk: &SecretKey, tweak: &[u8;32]) -> Result<Keypair, Error>` | Reconstruct a found payment's spend key `d = b_spend + t_k`. | `sp.rs:157` |
| `taproot_input_key(sk: SecretKey) -> SecretKey` | Normalize a Taproot input key to even Y (sender side). | `sp.rs:103` |

### chain.rs — Bitcoin read/write (bdk + esplora)

| Signature | Purpose | Loc |
| --- | --- | --- |
| `balance(ext_desc, int_desc) -> Result<Balance, Box<dyn Error>>` | Full-scan the descriptors and return confirmed + pending. | `chain.rs:40` |
| `build_signed(ext, int, to_addr, sats, max_fee_sats) -> Result<(Transaction, u64), _>` | Build+sign a P2TR payment (no broadcast); enforces the fee cap and mainnet guard. | `chain.rs:63` |
| `build_signed_to_sp(ext, int, scan, spend, sats, max_fee_sats, sp_utxos, sp_spend_sk) -> Result<(Transaction, u64, Address, Vec<OutPoint>), _>` | Build+sign a Silent Payments send (inputs pinned before the one-time addr). | `chain.rs:121` |
| `build_signed_spending_sp(ext, int, to_addr, sats, max_fee_sats, sp_utxos, sp_spend_sk) -> Result<(Transaction, u64, Vec<OutPoint>), _>` | Build+sign a normal send that may draw on received SP outputs. | `chain.rs:236` |
| `broadcast(tx: &Transaction) -> Result<Txid, _>` | Broadcast a signed tx (the only money-moving step). | `chain.rs:447` |
| `deposits_to(addr: &str) -> Result<Vec<Deposit>, _>` | Every deposit paying `addr`, newest first (stateless esplora read). | `chain.rs:467` |
| `rebroadcast_hex(hex: &str) -> Result<Rebroadcast, _>` | Rebroadcast a sidecar tx; classify Accepted vs provably-dead Rejected. | `chain.rs:513` |
| `confirmations(txid_str: &str) -> Result<u32, _>` | Confirmation count for a txid (0 if unconfirmed). | `chain.rs:581` |

### ledger.rs — signed append-only log

| Signature | Purpose | Loc |
| --- | --- | --- |
| `Status::from_confirmations(confs: u32) -> Status` | Map a confirmation count to Pending/Soft/Final. | `ledger.rs:48` |
| `Ledger::open(path) -> io::Result<Self>` | Open an unsigned ledger (tests / keyless callers). | `ledger.rs:156` |
| `Ledger::open_with_identity(path, identity: Keypair) -> io::Result<Self>` | Open a signed ledger; verify every line on load. | `ledger.rs:164` |
| `Ledger::append(&mut self, entry: Entry) -> io::Result<()>` | Sign, serialize, write, fsync one entry. | `ledger.rs:206` |
| `Ledger::balance(&self) -> u64` | Final received minus everything sent (Failed not debited). | `ledger.rs:481` |
| `Ledger::pending(&self) -> Vec<String>` | The work queue: in-flight txids (not yet Final/Failed). | `ledger.rs:505` |
| `Ledger::spent_since(&self, cutoff: u64) -> u64` | Total sats sent at/after `cutoff` (daily-limit fold). | `ledger.rs:530` |
| `Ledger::sp_balance(&self) -> u64` | Spendable SP balance (final, unspent). | `ledger.rs:398` |
| `Ledger::sp_incoming(&self) -> u64` | SP income booked but not yet final. | `ledger.rs:419` |
| `Ledger::sp_utxos(&self) -> Vec<SpUtxo>` | Unspent, final SP outputs with tweaks (spend candidates). | `ledger.rs:438` |
| `Ledger::record_received(&mut self, txid, sats, index) -> io::Result<bool>` | Book a chain-detected deposit as Pending Received (dedup). | `ledger.rs:322` |
| `Ledger::record_sp_received(&mut self, txid, vout, sats, tweak) -> io::Result<bool>` | Book a scanned SP output as Pending SpReceived (dedup). | `ledger.rs:342` |
| `Ledger::record_sp_spent(&mut self, txid, vout) -> io::Result<bool>` | Mark an SP outpoint spent (idempotent). | `ledger.rs:368` |
| `Ledger::next_address_index(&self) -> u32` | Next receive index (survives restart). | `ledger.rs:230` |
| `Ledger::write_sidecar / read_sidecar / remove_sidecar / list_sidecars` | Manage `pending/<txid>.tx` write-ahead signed-tx files. | `ledger.rs:568-616` |
| `reconcile(ledger: &mut Ledger) -> Result<usize, Box<dyn Error>>` | For each pending payment, re-check the chain, rebroadcast/advance/fail; drop orphan sidecars. | `ledger.rs:650` |

### pay.rs — ordered send path (build -> record -> broadcast)

| Signature | Purpose | Loc |
| --- | --- | --- |
| `send(led, ext, int, to, sats, max_fee_sats) -> Result<String, _>` | Plain-address send; returns the txid. | `pay.rs:33` |
| `sp_send(led, wallet, ext, int, code, sats, max_fee_sats) -> Result<String, _>` | Pay an SP code on-chain (no tunnel; payee may be offline). Enforces `SP_MIN_SATS` (330, `pay.rs:27`). | `pay.rs:78` |
| `send_spending_sp(led, wallet, ext, int, to, sats, max_fee_sats) -> Result<String, _>` | Send to a normal address, drawing on received SP outputs too. | `pay.rs:137` |

### policy.rs — spend gate

| Signature | Purpose | Loc |
| --- | --- | --- |
| `Policy::load() -> Result<Policy, _>` | Load `policy.json` (or permissive default). | `policy.rs:108` |
| `Policy::check_amount(&self, sats, spent_recent) -> Result<(), PolicyError>` | Per-payment + daily caps (before contacting the peer). | `policy.rs:119` |
| `Policy::check_address(&self, to) -> Result<(), PolicyError>` | Blocklist check once the destination is known. | `policy.rs:134` |
| `Policy::check_fee(&self, fee) -> Result<(), PolicyError>` | Fee cap once the tx is built. | `policy.rs:142` |
| `ensure_mainnet_capped(network, policy) -> Result<(), PolicyError>` | Mainnet fail-closed guard: require a spend cap AND a fee cap. Called inside every `chain::build_signed*`. | `policy.rs:93` |

### net.rs — transport-agnostic protocol

| Signature | Purpose | Loc |
| --- | --- | --- |
| `trait Wire { send; recv }` | Bidirectional message-framed channel (implemented by `FramedTunnel` and the test TCP wire). | `net.rs:18` |
| `run_receiver<W: Wire>(wire, rx, led) -> Result<(), _>` | Issue a fresh address, verify a Notify on-chain, book the real amount. | `net.rs:27` |
| `run_payer<W: Wire>(wire, ext, int, led, sats) -> Result<(), _>` | Gate policy, ask for an address, settle via `pay::send`, notify. | `net.rs:102` |

### tunnel.rs — WireGuard transport

| Signature | Purpose | Loc |
| --- | --- | --- |
| `identity(wallet) -> Result<(StaticSecret, PublicKey), _>` | The agent's WG static identity from the seed. | `tunnel.rs:48` |
| `parse_public_key(hex: &str) -> Result<PublicKey, _>` | Parse a peer's 64-hex WG public key. | `tunnel.rs:55` |
| `FramedTunnel::connect(sock, peer, secret, peer_pub) -> Result<Self, _>` | Initiator: open + handshake a tunnel to a known peer. | `tunnel.rs:159` |
| `FramedTunnel::accept_any(wallet, socket) -> Result<Option<(FramedTunnel, String)>, _>` | Responder on a shared socket: learn the dialer's key from the handshake. | `tunnel.rs:252` |
| `pay(wallet, ledger_path, peer_addr, peer_pub_hex, sats) -> Result<(), _>` | Dial a seller over WireGuard and run `net::run_payer`. | `tunnel.rs:351` |

### serve.rs / scan.rs / paywall.rs / fetch.rs

| Signature | Purpose | Loc |
| --- | --- | --- |
| `serve::run(wallet, ledger_path, bind, eps) -> Result<(), _>` | Resident seller daemon loop (republish / watch / accept). Never returns on its own. | `serve.rs:56` |
| `scan::scan_to_tip(wallet, led) -> Result<ScanReport, _>` | Scan blocks from checkpoint to tip, book SP income, track spends. | `scan.rs:74` |
| `scan::tx_pays_me(wallet, txid) -> Result<u64, _>` | Sats one tx pays us (no persistence); the paywall's verifier. | `scan.rs:128` |
| `scan::anchor_birth(wallet)` | Pin a fresh wallet's first scan to the current tip. | `scan.rs:144` |
| `paywall::run(listener, price_sats, body, wallet) -> Result<(), _>` | Serve one body for a fixed price over HTTP 402 (blocking, single-threaded). | `paywall.rs:52` |
| `fetch::fetch(wallet, led, url, max_sats) -> Result<FetchOut, _>` | GET a URL, auto-pay a cm 402 within `max_sats`, retry with the txid. | `fetch.rs:49` |

### storage.rs — seed at rest, config, identity

| Signature | Purpose | Loc |
| --- | --- | --- |
| `load_wallet() -> Result<Wallet, _>` | Resolve the acting identity and unlock it (`CM_MNEMONIC` > `seed.enc` > plaintext `mnemonic`). | `storage.rs:292` |
| `save_new_wallet(wallet, phrase, passphrase: Option<&str>) -> Result<PathBuf, _>` | Persist a new wallet (sealed `seed.enc` or 0600 `mnemonic`); set the `default` marker. | `storage.rs:202` |
| `save_encrypted / load_encrypted` | Argon2id + ChaCha20-Poly1305 seal / open of the mnemonic. | `storage.rs:31 / 53` |
| `wallet_dir(wallet) / ledger_path(wallet)` | `<root>/<id8>/` and its `ledger.jsonl`. | `storage.rs:181 / 190` |
| `wallet_ids() -> Vec<String>` | The 8-hex identity subdirectories on this machine. | `storage.rs:122` |
| `lock_dir(dir) -> Result<File, _>` | Exclusive non-blocking wallet lock (single writer). | `storage.rs:105` |
| `network() / network_label() / esplora_endpoint() / explorer_tx_url(txid)` | Active network + endpoints from env / defaults. | `storage.rs:239 / 253 / 264 / 279` |

### mcp.rs — MCP server and tool handlers

`run()` (`mcp.rs:55`) is the stdio JSON-RPC loop; `dispatch` (`mcp.rs:110`) routes
`initialize` / `ping` / `tools/list` / `tools/call`. Each tool reuses the CLI recipe:

| Tool | Handler | Loc |
| --- | --- | --- |
| `cm_setup` | `call_setup` -> `setup_report` | `mcp.rs:432 / 439` |
| `cm_pay` | `call_pay` -> `pay_peer` / `sp_pay` | `mcp.rs:843 / 876 / 942` |
| `cm_send` | `call_send` -> `send_payment` | `mcp.rs:734 / 758` |
| `cm_fetch` | `call_fetch` -> `fetch_report` | `mcp.rs:616 / 633` |
| `cm_paywall` | `call_paywall` (background thread) | `mcp.rs:651` |
| `cm_serve` | `call_serve` (background thread) | `mcp.rs:534` |
| `cm_balance` | `call_balance` -> `balance_report` | `mcp.rs:779 / 786` |
| `cm_collections` | `call_collections` -> `collections_report` | `mcp.rs:991 / 998` |
| `cm_confs` | `call_confs` -> `confs_report` | `mcp.rs:957 / 974` |
| `cm_id` | `call_id` | `mcp.rs:507` |
| `cm_address` | `call_address` | `mcp.rs:522` |

`cm_serve` and `cm_paywall` are one-per-session, guarded by the `SERVING` /
`PAYWALL` atomics (`mcp.rs:38 / 42`). See [mcp-usage.md](mcp-usage.md).

---

## 4. CLI commands

From `main.rs` (dispatch in `run`, `main.rs:50`). Unknown/no subcommand prints the
help banner and exits 2.

| Command | Args | Purpose | Loc |
| --- | --- | --- | --- |
| `cm setup` | none | Create a wallet if none exists, then print network, card key, funding address, balance, and how to transact. | `main.rs:53` |
| `cm balance` | none | On-chain balance plus scanned silent-payment income (+ not-yet-spendable incoming). | `main.rs:104` |
| `cm id` | none | Print the card key and the static sp code. | `main.rs:145` |
| `cm publish` | `[host:port …]` | Sign + put the card to the DHT with zero or more endpoints. | `main.rs:153` |
| `cm serve` | `[--bind addr] [--ep host:port]…` | Resident seller daemon (republish, watch chain, accept tunnels). `--ep` repeatable; default bind `0.0.0.0:51820`. | `main.rs:179` |
| `cm pay` | `<sp-code \| card-key \| pubkey@host:port> <sats>` | Pay: SP code on-chain, card key via DHT (sp code or tunnel), or a direct endpoint. | `main.rs:204` |
| `cm fetch` | `<url> [--max-sats N]` | GET a URL, auto-paying a cm HTTP 402 (default cap 10000 sats). | `main.rs:259` |
| `cm paywall` | `<price_sats> [--port N] [--body S]` | Sell one body over HTTP 402 (blocking). Default port 8402. | `main.rs:286` |
| `cm confs` | `<txid>` | Confirmation count + status (pending/soft/final/failed); stateless. | `main.rs:313` |
| `cm mcp` | none | Run the stdio MCP server (11 tools). | `main.rs:328` |

---

## 5. Environment variables

Every `CM_*` (and `HOME`) the code reads. All are optional except where noted.

| Variable | Meaning | Read at |
| --- | --- | --- |
| `CM_NETWORK` | Active network: `mainnet` (default) \| `testnet` \| `signet`. | `storage.rs:240` |
| `CM_PASSPHRASE` | Passphrase that seals / unlocks the encrypted seed. **Required on mainnet** (`cm setup` refuses without it; `seed.enc` cannot unlock without it). | `main.rs:61`, `storage.rs:303`, `mcp.rs:443` |
| `CM_HOME` | Absolute path overriding the config root (run several agents on one machine). | `storage.rs:88` |
| `CM_ID` | Identity prefix selecting which wallet to act as when several exist. | `storage.rs:297` |
| `CM_MNEMONIC` | Explicit plaintext-mnemonic escape hatch; wins over the on-disk wallet. | `storage.rs:293` |
| `CM_ESPLORA` | Esplora endpoint override (else a per-network public default). | `storage.rs:265` |
| `CM_POLICY` | Path to `policy.json` (else `<root>/policy.json`). **Effectively required on mainnet**, since the fail-closed guard needs a spend cap + fee cap. | `policy.rs:109` (via `config_path`, `storage.rs:230`) |
| `HOME` | Base of the default config root when `CM_HOME` is unset. | `storage.rs:94` |

Mainnet fail-closed summary: a mainnet send needs `CM_PASSPHRASE` (to unlock the
sealed seed) plus a `policy.json` (via `CM_POLICY` or the default path) that sets a
spend cap and a fee cap; otherwise `ensure_mainnet_capped` (`policy.rs:93`) refuses
before any money moves.

---

## 6. On-disk layout

Config root (`config_root`, `storage.rs:85`): `CM_HOME` if set, else
`~/.config/computermoney/`.

```
<root>/
  default                 marker naming the identity used when CM_ID is unset
  policy.json             spend policy (or CM_POLICY path)
  <id8>/                  one directory per identity (first 8 hex of cm id)
    seed.enc              sealed mnemonic (salt || nonce || ciphertext), when a passphrase is set
    mnemonic              plaintext mnemonic, 0600 (test networks only; refused on mainnet)
    ledger.jsonl          append-only signed economic log (the source of truth)
    scan.json             highest fully-scanned block height (SP scan checkpoint)
    lock                  exclusive single-writer lock file
    pending/
      <txid>.tx           write-ahead raw consensus hex of a broadcast-pending tx (sidecar)
```

- Identity directory name = first 8 hex chars of `cm id` (`wallet_dir`, `storage.rs:181`); depends on coin type, so mainnet and test wallets land in different dirs.
- Ledger path (`ledger_path`, `storage.rs:190`) and SP checkpoint (`checkpoint_path`, `scan.rs:264`) both sit inside `<id8>/`.
- The sidecar dir is `pending/` beside the ledger (`sidecar_dir`, `ledger.rs:554`).
- Ledger lines are identity-signed; `open_with_identity` refuses foreign or tampered lines, so two identities never share a file.
