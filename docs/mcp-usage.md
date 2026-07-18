---
title: MCP usage
nav_order: 3
---

Drive the whole wallet in plain language. `cm mcp` runs the same `cm` binary as a
[Model Context Protocol](https://modelcontextprotocol.io) server over stdio, so an MCP
client (Claude Code, Claude Desktop, your own agent) calls tools instead of you typing
`cm`. The seed and passphrase are never tool arguments — the wallet unlocks once at startup
and is held for the process lifetime.

## The tools

| Tool | Args | Role | What it does |
|---|---|---|---|
| `cm_pay` | `card_key` (64-hex), `sats` | buyer | **the flagship**: resolve the card on the DHT, tunnel over WireGuard, settle on L1. Returns txid + explorer URL. |
| `cm_send` | `address`, `sats` | buyer | raw on-chain send to an address you already hold. Returns txid + explorer URL. |
| `cm_balance` | — | either | confirmed + pending balance on the active network. |
| `cm_confs` | `txid` | either | confirmation count + status (pending/soft/final), and advances the ledger. |
| `cm_collections` | — | seller | per issued receive index: address, awaiting/paid, txid, sats. How the seller agent sees a payment arrive. |

## One thing MCP cannot do: start the seller

The seller's body is `cm serve` — a **resident daemon**, not an MCP tool. An MCP server is
request/response; a daemon would block it. So the split is deliberate:

- **buyer = pure MCP** — the agent calls `cm_pay` / `cm_send`; no CLI.
- **seller = `cm serve` daemon (one CLI line) + MCP for monitoring** — the daemon accepts
  tunnels and books deposits from the chain; the seller agent watches with `cm_collections`.

You cannot run the full two-agent flow with *zero* CLI: the seller daemon is the one process
that must be started from a shell. Everything a person *asks* still goes through MCP.

## Setup (signet demo wallet)

The installer already registered a `computermoney` MCP server on a throwaway **signet** wallet.
Two notes:

1. **Restart your MCP client to load all five tools.** An older build exposed only
   `cm_send` + `cm_balance`; the current binary adds `cm_pay`, `cm_confs`, `cm_collections`.
   The registration points at the `cm` binary path, so restarting relaunches `cm mcp` with
   the latest build.
2. Manual registration (Claude Desktop, another client) — point the config at the binary:

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

## Demo A — pure MCP, one wallet (works immediately)

No daemon, no second agent. Just talk to the buyer wallet:

- *"what's my computermoney balance?"* → `cm_balance`
- *"send 1000 sats to `<signet-address>`"* → `cm_send` → returns a txid + explorer link
- *"how many confirmations on `<txid>`?"* → `cm_confs`

This shows natural-language Bitcoin settlement through MCP. It is a raw on-chain send, not the
discover→talk→settle pipeline (that is Demo B).

## Demo B — the full pipeline, agent to agent

The money shot: one agent pays another over **DHT → WireGuard → Bitcoin L1**, driven by a
plain sentence on the buyer side.

**1. Start the seller daemon (CLI, one line).** A second identity in its own store:

```sh
export CM_NETWORK=signet
CM_HOME=~/cm-seller cm setup                                   # create the seller wallet
CM_HOME=~/cm-seller cm id                                      # -> the seller CARD KEY (copy it)
CM_HOME=~/cm-seller cm serve --bind 127.0.0.1:51820 --ep 127.0.0.1:51820 &
```

**2. (Optional) register the seller as its own MCP server** so its agent can watch arrivals:

```sh
claude mcp add -s user computermoney-seller \
  -e CM_NETWORK=signet -e CM_HOME="$HOME/cm-seller" -- "$HOME/.cargo/bin/cm" mcp
```

**3. Pay from the buyer agent, in language:**

> *"pay 5000 sats to `<seller-card-key>`"*

The client calls `cm_pay(card_key, 5000)`, which resolves the seller's card on the DHT,
opens the WireGuard tunnel to `127.0.0.1:51820`, asks for a fresh address, broadcasts 5000
signet sats, and returns the txid.

**4. Confirm arrival from the seller agent:**

> *"did a payment land? show collections"* → `cm_collections`
> *"confirmations on `<txid>`?"* → `cm_confs`

The seller daemon's log also prints `verified <txid> pays 5000 sat to our address` — the
receipt is taken from the chain, never from the buyer's claim.

## Watching each layer work

The pipeline is three layers you can see move independently. For a demo, keep the seller
daemon's terminal visible and put these next to it.

| Layer | What proves it | Where to look |
|---|---|---|
| **DHT** (discover) | seller prints `[serve] published card <key> @ 127.0.0.1:51820`; the buyer prints `resolving card <8hex>… (DHT)` then `dialing …`. The card is a signed BEP-44 record on the public BitTorrent DHT — no server holds it. | daemon log + `cm_pay` progress |
| **WireGuard** (talk) | seller prints `[serve] session opened with <buyer-wg-key>`. And the wire is genuinely encrypted — sniff it: `sudo tcpdump -i lo0 -X udp port 51820` shows ciphertext, never the JSON messages. | logs + `tcpdump` |
| **Bitcoin L1** (settle) | `cm_pay` returns `txid …` + an explorer URL — open it and watch the tx pay the seller's address. The seller prints `verified <txid> pays 5000 sat to our address`, and `cm_confs` walks it to *final*. | block explorer + logs |

## Notes

- **Signet vs testnet.** The demo wallet is signet (30-second blocks, reliable
  [faucet](https://faucet.mutinynet.com/), 3-conf final ≈ 90 s). Testnet3 works the same way
  (`CM_NETWORK=testnet`) but is slower and its faucets are often dry.
- **`cm_pay` not listed?** Restart the client (see Setup step 1).
- **`no card found on the DHT`** — give the seller daemon 30–60 s to propagate after start,
  then retry. To skip the DHT and exercise only WireGuard + L1, there is no MCP form; use the
  CLI direct path `cm pay <wg-pubkey>@127.0.0.1:51820 <sats>`.
- **Mainnet** is opt-in and fail-closed: unlock a sealed seed with `CM_PASSPHRASE` and set a
  `CM_POLICY` spend cap, or `cm` refuses to broadcast.
