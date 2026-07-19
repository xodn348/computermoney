# Changelog

All notable changes to `computermoney`. Milestones follow the git tags (`v1`, `v2`).

## v2 (2026-07-19)

**v2 turns `cm` from a keyed Bitcoin wallet into a full autonomous agent-to-agent
payment rail.** Two AI agents can now discover each other with no directory, settle real
bitcoin with no processor or account, and drive the whole thing in plain language through
MCP. The seed is the only identity, for both the money and the channel.

### Headline capabilities added in v2

- **Discover with no server.** A peer *is* its card key (a 32-byte ed25519 public key). `cm`
  publishes a signed card (silent-payment code plus endpoints) to the BitTorrent Mainline DHT,
  and anyone holding the key resolves it. No central directory to trust or take down.
- **Pay a peer who is offline.** Silent Payments (BIP-352) give the payee a fresh one-time
  address per payment from one static code. The payer settles on-chain; the payee scans for
  its income later. No live handshake required.
- **Receive and re-spend automatically.** Money received by silent payment surfaces in the
  balance and spends like any other funds: `cm pay`, `cm send`, and `cm fetch` all draw on it.
- **Sell and buy data over HTTP 402.** A seller serves a body behind an HTTP 402 that carries
  its terms; a buyer's agent auto-pays on-chain within its cap and gets the content back. No
  signup, no card, no human in the loop.
- **Driven entirely by an agent.** The full pipeline is exposed as 11 plain-language MCP tools,
  so "pay 5000 sats to `<card-key>`" or "sell `report.json` for 800 sats" just works. The seed
  never crosses the tool boundary.
- **Mainnet by default, fail-closed.** `cm` runs on Bitcoin mainnet out of the box. On mainnet a
  send is refused before any signing unless the policy sets both a spend cap and a fee cap, so
  an agent cannot talk its way past the limits.
- **Crash-safe settlement.** A write-ahead ledger, an explicit `Failed` state, and fee guards
  make the send path safe to interrupt on real money.

### The three layers

| Layer | Job | How |
|---|---|---|
| **Discover** | find a peer with no directory | Mainline DHT, card key = ed25519 pubkey, signed [BEP-44](https://www.bittorrent.org/beps/bep_0044.html) record |
| **Talk** | exchange an address or notice | WireGuard tunnel keyed by the same seed, messages only, never coins; the offline path skips it |
| **Settle** | move the money | one Taproot transaction on Bitcoin L1; the chain, not any peer's word, is the source of truth |

Confirmation ladder: `0 = Pending`, `1-2 = Soft`, `3+ = Final`, plus `Failed`.

### Added

- `src/discover.rs`: DHT discovery. Resolve a peer by its card key, no central server.
- `src/sp.rs`: Silent Payments (BIP-352). Static code in, one-time addresses out.
- `src/scan.rs`: chain scanning that credits silent-payment income, including money received
  while offline.
- `src/paywall.rs`, `src/fetch.rs`: the HTTP 402 seller and buyer.
- `src/serve.rs`: the `cm serve` seller daemon (publish, accept buyers, watch the chain).
- `src/pay.rs`: the end-to-end pay path (discover then settle).
- Docs site on GitHub Pages (`docs/`, just-the-docs): architecture, payment flow, reference,
  MCP usage, and a two-terminal walkthrough, plus `llms.txt` / `llms-full.txt` for agents.
- Two demo clips in the README (pay a DHT peer; sell data over HTTP 402), recorded on signet.
- `THIRD-PARTY-LICENSES.md`, `TRADEMARK.md`, `CONTRIBUTING.md` (DCO), and a DCO check.

### Changed

- **Relicensed to AGPL-3.0-only**, Copyright (C) 2026 Ebsilon, Inc.
- `src/mcp.rs`: grew to the full 11-tool surface (`cm_setup`, `cm_pay`, `cm_send`, `cm_fetch`,
  `cm_paywall`, `cm_balance`, `cm_collections`, `cm_confs`, `cm_id`, `cm_address`, `cm_serve`).
- CLI trimmed to the pipeline: `setup`, `id`, `publish`, `serve`, `pay`, `fetch`, `paywall`,
  `balance`, `confs`, `mcp`.
- `src/ledger.rs`: write-ahead ledger and a `Failed` status so an interrupted mainnet send is
  recoverable.
- `src/policy.rs`: mainnet guard is now fail-closed (spend cap plus fee cap required); signet
  and testnet stay permissive.
- `src/chain.rs`, `src/tunnel.rs`, `src/net.rs`, `src/storage.rs`, `src/wallet.rs`: reworked to
  carry the discover/talk/settle pipeline.
- README rewritten mainnet-first, with the demos and the fail-closed policy example.

### Removed

- `src/demo.rs`: the old canned `cm demo` command, replaced by the real two-terminal walkthrough.

## v1 (2026-07-06)

Baseline: an identity-keyed self-custodial wallet with a WireGuard tunnel, basic MCP
registration, and a plaintext wallet on test networks. No DHT discovery, no Silent Payments,
no HTTP 402, no seller daemon.
