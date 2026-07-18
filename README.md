# computermoney

[![Docs](https://img.shields.io/badge/docs-live-2ea44f)](https://xodn348.github.io/computermoney/) [![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)

AI agent payment rail with Bitcoin. No Stripe, Coinbase, Paypal and other external payment companies are needed.

## Demo

An agent driving `cm` in plain language, end to end: no processor, no account, real bitcoin.

_The two clips are recorded on a test network (signet), so the coins are worthless. On mainnet the same commands and the same flow move real bitcoin._

**1. Pay a peer found on the DHT.** The agent reads B's card from the DHT and pays its static
silent-payment code on Bitcoin L1. B can be offline.


https://github.com/user-attachments/assets/8edbbf52-0b79-4d43-97a9-a3368602788c


**2. Sell data over HTTP 402.** A seller serves a dataset behind a 402; the buyer's agent
auto-pays within its cap and gets the file back.


https://github.com/user-attachments/assets/80b223b2-cc49-4f2d-90b2-2d435d25d60c


## How it works

Three layers, each doing one job: **discover** on the DHT, **talk** over WireGuard, **settle**
on Bitcoin L1.

```
   Agent A (payer)                                    Agent B (payee)
   seed --> keys                                      seed --> keys
        |                                                  |
        |  (1) DISCOVER  ----- Mainline DHT ----------->   |  resolve B's card key
        |      fetch B's card: sp code + endpoint          |  -> sp code + endpoint
        |                                                  |
        |  (2) TALK      <---- WireGuard tunnel ------->    |  answer with an address
        |      messages only, LAN/localhost, no internet    |  (live sessions only;
        |                                                  |   the offline path skips it)
        |  (3) SETTLE    ----- Bitcoin L1 (Taproot) --->   |  scan / reconcile
        |      one tx per payment                           |  the chain is the truth
        v                                                  v
   +---------------------- Bitcoin network -----------------------+
   |   0 / 1 / 3 confirmations  =  Pending / Soft / Final         |
   +-------------------------------------------------------------+
```

**1. Discover — Mainline DHT.** A peer *is* its card key (a 32-byte ed25519 public key).
`cm` publishes a signed card (the peer's silent-payment code and network endpoints) to the
BitTorrent Mainline DHT under that key, and anyone holding the key resolves it, with no
central directory to trust. More: [BEP 44 — DHT storage](https://www.bittorrent.org/beps/bep_0044.html).

**2. Talk — WireGuard.** When both agents are online and want a live exchange, `cm` opens a
WireGuard tunnel keyed by the same seed. It carries messages only (an address request, a
payment notice), never coins, and runs on a LAN or localhost with no internet. The offline
path skips this layer entirely. More: [WireGuard whitepaper](https://www.wireguard.com/papers/wireguard.pdf).

**3. Settle — Bitcoin L1.** Every payment is one Taproot transaction on Bitcoin mainnet. The
chain, not any peer's message, is the source of truth: the receiver credits the real on-chain
output, and confirmations advance it. Silent Payments
([BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)) give the payee a
fresh one-time address per payment from one static code, so it can be paid offline and scan
for its income later.

**Also over HTTP 402.** `cm` can sell and buy data directly: a seller serves a body behind an
HTTP 402 response that carries its sp code, and a buyer's `cm fetch` pays it on-chain within a
cap and gets the content back. No signup, no card. See [Selling data](#selling-data-step-by-step).

## Install

_Supported platforms: Linux and macOS (Windows via WSL). The installer is a POSIX shell script; the userspace WireGuard stack needs no kernel module._

```sh
curl -fsSL https://raw.githubusercontent.com/xodn348/computermoney/main/install.sh | sh
```

Builds and installs the `cm` binary (needs a [Rust toolchain](https://rustup.rs) and a C
compiler) and, if Claude Code is detected, registers the `cm mcp` server. `cm` runs on
**Bitcoin mainnet by default**, which is the real product. So the first run is safe, the
one-line installer opts the demo wallet down to **signet** (worthless coins) that you can fund
from the [faucet](https://faucet.mutinynet.com/). When you want real bitcoin, set up
[mainnet](#mainnet-real-bitcoin).

## Using it

Once `cm mcp` is registered, you drive the wallet by talking to your agent, with no shell, no
flags, and no key handling.

| You say | What `cm` does |
|---|---|
| *"set up my wallet"* | creates the wallet, prints your card key, sp code, and funding address |
| *"what's my address?"* | your on-chain address, to top up from an exchange |
| *"pay 5000 sats to `<card-key>`"* | resolves the peer on the DHT and settles one Taproot tx, returns the txid |
| *"did anyone pay me?"* / *"what's my balance?"* | scans the chain and shows received income, including money paid while you were offline |
| *"sell the contents of `report.json` for 800 sats"* | serves it behind an HTTP 402 that carries your sp code |
| *"fetch `<url>` and pay if it asks"* | pays the 402 within your cap and returns the content |

## Selling data, step by step

One agent can sell a dataset to another for bitcoin, end to end, with no human in the loop.
Here is the exact sequence and the natural-language prompt that drives each step.

**Seller (agent B)**

1. *"sell the contents of `report.json` for 800 sats"* → B reads the file and opens an HTTP
   402 endpoint (`cm_paywall`), which returns a URL. Any GET without payment gets B's terms:
   ```
   HTTP/1.1 402 Payment Required
   {"cm402":1,"sats":800,"pay_to":"sp1…","network":"mainnet"}
   ```

**Buyer (agent A)**

2. *"fetch `http://<B-host>:8402` and pay if it asks"* → A GETs the URL (`cm_fetch`), reads the
   402 terms, and pays 800 sats **on-chain to B's sp code**, staying within A's spend cap.
3. A retries the GET with proof of payment: `X-Payment: <txid>`.

**Seller (agent B)**

4. B verifies that txid against its own scan key: the transaction must pay B at least 800 sats,
   and each txid is redeemable once. If it checks out, B returns the dataset.

**Result:** A has the data; B earned 800 sats that spend like any other funds (B can pay it
forward immediately with *"pay …"*). The payment terms travelled inside the protocol; no key,
invoice, or account was handed around.

## Mainnet (real bitcoin)

`cm` is a mainnet wallet by default; the one-line installer only opts down to signet so the
first run is safe. For real money, register the MCP server with `CM_NETWORK=mainnet`, unlock a
sealed seed with a passphrase, and **set the caps**: on mainnet `cm` refuses to broadcast
without them.

```json
"env": {
  "CM_NETWORK": "mainnet",
  "CM_PASSPHRASE": "<passphrase that seals the seed>",
  "CM_POLICY": "/abs/path/to/policy.json"
}
```
```json
// policy.json: limits the agent cannot talk its way around
{ "max_payment_sats": 50000, "daily_limit_sats": 200000, "max_fee_sats": 5000 }
```

The guard is **fail-closed**: on mainnet a send is rejected before any signing unless the policy
sets a spend cap (`max_payment_sats` or `daily_limit_sats`) and a fee cap (`max_fee_sats`). An
absent or empty `policy.json` (`{}`) counts as uncapped and is refused, at the single chokepoint
every send path funnels through. Signet and testnet stay permissive for experimentation.

## Commands

```
cm setup                          create a wallet; print identity, sp code, address, balance
cm id                             print your card key and static sp code (the handles you share)
cm publish [host:port ...]        sign and put your card (sp code, endpoints) to the DHT
cm serve [--bind a] [--ep a]      run the seller daemon: publish, accept buyers, watch the chain
cm pay <sp-code | card-key | pubkey@host:port> <sats>   pay a peer (sp code / card key may be offline)
cm fetch <url> [--max-sats N]     GET a URL, auto-paying an HTTP 402 within the cap
cm paywall <price> [--port N] [--body S]   sell one body over HTTP 402
cm balance                        scan the chain, print on-chain + silent-payment balance
cm confs <txid>                   confirmation count and status (pending / soft / final)
cm mcp                            run as an MCP server so an agent drives it in plain language
```

## MCP

`cm mcp` exposes the whole pipeline to any MCP client (Claude Code, Claude Desktop, or your
own agent) as plain-language tools, so *"pay 5000 sats to `<card-key>`"* just works with no
shell and no key handling. The seed never crosses the tool boundary. See the
[MCP guide](https://xodn348.github.io/computermoney/mcp-usage.html).

## Docs

Full docs, including the payment flow, MCP usage, and a runnable walkthrough:
**[xodn348.github.io/computermoney](https://xodn348.github.io/computermoney/)**. For agents,
an AI-readable map lives at [`llms.txt`](https://xodn348.github.io/computermoney/llms.txt).

## License

Licensed under the [GNU AGPL v3.0](LICENSE), Copyright (C) 2026 Ebsilon, Inc.

"computermoney" is a trademark of Ebsilon, Inc. ([trademark policy](TRADEMARK.md)).
Third-party notices: [`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md). Contributing
requires a DCO sign-off ([`CONTRIBUTING.md`](CONTRIBUTING.md)).
