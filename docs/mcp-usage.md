---
title: MCP usage
nav_order: 5
---

# MCP usage

Drive the whole wallet in plain language. `cm mcp` runs the same `cm` binary as a
[Model Context Protocol](https://modelcontextprotocol.io) server over stdio, so an MCP
client (Claude Code, Claude Desktop, your own agent) calls tools instead of you typing
`cm`. The wallet unlocks once at startup (or lazily on the first call that can unlock it)
and is held for the process lifetime. The seed and passphrase are never tool arguments.

For the money path behind these tools (discover on the DHT, talk over WireGuard, settle on
Bitcoin L1, or pay a Silent Payments code offline) see [Payment flow](payment-flow.md). For
the module/function/CLI/env reference see [Reference](reference.md).

## The tools

The server exposes 11 tools (registered in `src/mcp.rs:169-367`, allowlisted in
`src/mcp.rs:376-389`). Tools that take no arguments have an explicit empty-object
`inputSchema`. Every `sats` field is an integer with `minimum: 1`.

| Tool | Params | What it does |
|---|---|---|
| `cm_setup` | none | Create this agent's wallet if it has none, then report network, card key, static sp code, funding address, and balance, and publish the card to the DHT (best effort). Call this first, once. On mainnet the seed is sealed, so `CM_PASSPHRASE` must be in the server's registration env. (`mcp.rs:173`) |
| `cm_pay` | `peer` (string, required), `sats` (int ≥1, required) | Pay a peer `sats` satoshis. `peer` is any of: an `sp1`/`tsp1` Silent Payments code (on-chain, payee may be offline), a 64-hex card key (resolved on the DHT; on-chain if the card carries an sp code, else a WireGuard tunnel), or a `wg-pubkey@host:port` direct link (tunnel, no DHT). Draws on ordinary funds and received silent-payment income. Returns txid + explorer URL. (`mcp.rs:184`) |
| `cm_send` | `address` (string, required), `sats` (int ≥1, required) | Raw on-chain send of `sats` to a Bitcoin `address` you already hold. Draws on ordinary funds and received silent-payment income. Returns txid + explorer URL. (`mcp.rs:210`) |
| `cm_fetch` | `url` (string, required), `max_sats` (int ≥1, optional, default 10000) | GET `url`; a normal 200 is returned as-is, a cm HTTP 402 is auto-paid on-chain within `max_sats` and the URL is retried until the content comes back. Returns the body, plus sats paid and txid when a payment happened. (`mcp.rs:234`) |
| `cm_paywall` | `price_sats` (int ≥1, required), `body` (string, optional, default placeholder), `port` (int ≥1, optional, default 8402) | Sell one `body` for `price_sats` over HTTP 402 for the rest of this session (background thread; one per session). Returns a URL whose unpaid GET yields a 402 carrying your sp code and price; a paid retry (header `X-Payment: <txid>`) yields the content. Listen IP is auto-detected. (`mcp.rs:259`) |
| `cm_balance` | none | Report spendable balance on the active network: confirmed + pending on-chain plus received silent-payment income. Scans the chain for offline SP income as part of the call; income received but not yet spendable (fewer than 3 confirmations) is shown on its own `incoming` line. (`mcp.rs:288`) |
| `cm_collections` | none | Scan the chain for money paid to you and report every received payment (ordinary deposits and offline silent-payment income) as JSON `{ scan, collections[] }`. Books newly found silent payments before reporting. This is how a seller agent sees a payment arrive. (`mcp.rs:301`) |
| `cm_confs` | `txid` (string, required) | Report `txid`'s confirmation count and status (pending/soft/final/failed) and advance the ledger's recorded status. (`mcp.rs:310`) |
| `cm_id` | none | Print this agent's card key (the 64-hex identity a peer resolves on the DHT) and its static sp code. Both are payee handles. (`mcp.rs:327`) |
| `cm_address` | none | Print the wallet's on-chain funding address (receive index 0), for topping up from an exchange or faucet. (`mcp.rs:335`) |
| `cm_serve` | `bind` (string, optional, default `0.0.0.0:51820`), `ep` (string, optional, auto-detected) | Start the seller daemon in the background for the rest of this session (one per session): publish the card on the DHT, accept WireGuard tunnels, and watch the chain. Only needed for live peer sessions; for plain get-paid, `cm_setup`'s sp code is enough and you can stay offline. Returns the card key, endpoint, and a direct link. (`mcp.rs:342`) |

Notes on the two long-running tools:

- `cm_serve` and `cm_paywall` each spawn a background thread that lives until the MCP
  process exits with its client session. A second call to either returns "already
  serving" / "already running" instead of racing a duplicate listener (`mcp.rs:38-42`).
- `cm_setup`, `cm_serve`, and `cm_paywall` run before the shared wallet unlock, so they
  work even when the session started with no wallet yet (`mcp.rs:395-402`).

## Plain-language examples

| You say | The agent calls |
|---|---|
| "set up my wallet / what's my card key and sp code?" | `cm_setup` |
| "what's my balance?" | `cm_balance` |
| "pay 5000 sats to `sp1q…` (or a 64-hex card key)" | `cm_pay(peer, 5000)` |
| "send 1000 sats to `<address>`" | `cm_send(address, 1000)` |
| "buy the data at `<url>`, up to 2000 sats" | `cm_fetch(url, 2000)` |
| "sell this text for 500 sats" | `cm_paywall(500, body)` |
| "did anyone pay me?" | `cm_collections` |
| "how many confirmations on `<txid>`?" | `cm_confs(txid)` |
| "start accepting live peer sessions" | `cm_serve` |

## Environment and setup

Register `cm mcp` as an MCP server with the `cm` binary path and the env that pins the
wallet, network, and home directory. In Claude Code:

```sh
claude mcp add -s user computermoney \
  -e CM_NETWORK=signet -- "$HOME/.cargo/bin/cm" mcp
```

Manual registration (Claude Desktop, another client) points the config at the binary:

```json
{
  "mcpServers": {
    "computermoney": {
      "command": "/Users/you/.cargo/bin/cm",
      "args": ["mcp"],
      "env": { "CM_NETWORK": "signet" }
    }
  }
}
```

To run a second identity (for example a seller alongside a buyer) register a second server
with its own `CM_HOME`:

```sh
claude mcp add -s user computermoney-seller \
  -e CM_NETWORK=signet -e CM_HOME="$HOME/cm-seller" -- "$HOME/.cargo/bin/cm" mcp
```

### Environment variables the code reads

| Variable | Read at | Meaning |
|---|---|---|
| `CM_NETWORK` | `storage.rs:240` | Active Bitcoin network: `mainnet` (default) `\|` `testnet` `\|` `signet`. Anything unset/unrecognized is mainnet. |
| `CM_PASSPHRASE` | `main.rs:61`, `mcp.rs:443`, `storage.rs:303` | Unlocks (and, at setup, seals) the encrypted seed. Required on mainnet; absent on signet/testnet the mnemonic is stored plaintext. |
| `CM_POLICY` | `policy.rs:109` | Path override for the policy file (default `~/.config/computermoney/policy.json`). |
| `CM_HOME` | `storage.rs:88` | Absolute path overriding the config root, so several agents can run on one machine without sharing state. |
| `CM_MNEMONIC` | `storage.rs:293` | Explicit escape hatch: a plaintext mnemonic that wins over the stored wallet. Refused on mainnet. |
| `CM_ID` | `storage.rs:297` | Identity prefix to pick among several wallets under one home. |
| `CM_ESPLORA` | `storage.rs:265` | Override the esplora endpoint used for chain sync. |

The passphrase and seed come from this registration env, never from a tool call. Per the
server's own `initialize` instructions, an agent should not set env vars or run shell
commands to "prepare" cm; it just calls the tools.

### Mainnet fail-closed spend cap

The spend policy is data loaded from `~/.config/computermoney/policy.json` (override with
`CM_POLICY`). An absent file deserializes to a permissive default: no restrictions, which
is fine for a signet/testnet demo (`policy.rs:106-115`). The optional fields are
`max_payment_sats`, `daily_limit_sats`, `max_fee_sats`, and `blocked_addresses`; each
missing field turns that limit off (`policy.rs:27-38`).

On mainnet the wallet fails closed. `ensure_mainnet_capped` (`policy.rs:93-104`) refuses a
broadcast unless the effective policy sets **at least one spend cap** (`max_payment_sats`
or `daily_limit_sats`) **and** a fee cap (`max_fee_sats`). An absent or empty (`{}`)
policy is the permissive default, so it is rejected on mainnet with a typed error:
`MainnetUncapped` when no spend cap is set, `MainnetNoFeeCap` when a spend cap is set but
the fee is left unbounded. Signet and testnet stay permissive by design and the guard
never trips (`policy.rs:247-251`). So on mainnet, write a `policy.json` with at least one
spend cap and a fee cap before any send will broadcast.

The other gates run on every send too: `check_amount` enforces the per-payment cap and a
rolling 24-hour daily cap (`DAILY_WINDOW_SECS = 86_400`), `check_address` enforces the
blocklist, and `check_fee` bounds the fee once the transaction is built
(`policy.rs:119-149`).

## Safety

- **The seed never crosses the tool boundary.** No tool takes a mnemonic, seed, or
  passphrase argument. The wallet is unlocked once from the server's registration env
  (`CM_PASSPHRASE`/`CM_MNEMONIC`) and reused for the process lifetime (`mcp.rs:16-21`,
  `55-69`).
- **The spend cap has a single choke point.** `ensure_mainnet_capped` is the one
  definition of the mainnet fail-closed guard, and every send path routes through
  `chain::send`, which calls it (`policy.rs:84-104`). The MCP `cm_send` and Silent
  Payments paths additionally gate `check_amount` + `check_address` up front
  (`mcp.rs:758-775`, `942-953`); the tunnel `cm_pay` path gates inside `net::run_payer`,
  so the policy is enforced exactly once regardless of which tool moved the money.
