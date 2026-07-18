# computermoney

AI agent payment rail with Bitcoin. No Stripe, Coinbase, Paypal and other external payment companies needed.

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

```sh
curl -fsSL https://raw.githubusercontent.com/xodn348/computermoney/main/install.sh | sh
```

Builds and installs the `cm` binary (needs a [Rust toolchain](https://rustup.rs) and a C
compiler) and, if Claude Code is detected, registers the `cm mcp` server. It starts you on a
**signet demo wallet** so you can try everything with worthless coins; fund the printed address
from the [faucet](https://faucet.mutinynet.com/). Move to real bitcoin in
[Going to mainnet](#going-to-mainnet-real-bitcoin).

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

## Going to mainnet (real bitcoin)

The installer wallet is signet. For real money, register the MCP server with
`CM_NETWORK=mainnet`, unlock a sealed seed with a passphrase, and **set a spend cap**: on
mainnet `cm` refuses to broadcast without one.

```json
"env": {
  "CM_NETWORK": "mainnet",
  "CM_PASSPHRASE": "<passphrase that seals the seed>",
  "CM_POLICY": "/abs/path/to/policy.json"
}
```
```json
// policy.json — a limit the agent cannot talk its way around
{ "max_payment_sats": 50000, "daily_limit_sats": 200000 }
```

The cap is **fail-closed**: an absent or empty policy on mainnet rejects the send before any
signing, at the single chokepoint every send path funnels through. Signet and testnet stay
permissive for experimentation.

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
shell and no key handling. The seed never crosses the tool boundary. See
[`docs/mcp-usage.md`](docs/mcp-usage.md).

## Docs

Docs site: **[xodn348.github.io/computermoney](https://xodn348.github.io/computermoney/)**.

- [`docs/payment-flow.md`](docs/payment-flow.md) — the function-by-function order inside `cm pay` and the seller daemon.
- [`docs/mcp-usage.md`](docs/mcp-usage.md) — driving the wallet in plain language over MCP.
- [`docs/demo-2-terminal.md`](docs/demo-2-terminal.md) — try the full pipeline on one machine (signet).
- [`docs/demo-video-script.md`](docs/demo-video-script.md) — shot list for the demo video.

For AI agents: [`docs/llms.txt`](docs/llms.txt) (a map of the docs) and [`docs/llms-full.txt`](docs/llms-full.txt) (the full text inlined).

## License

**[GNU AGPL v3.0](LICENSE)**, Copyright (C) 2026 Ebsilon, Inc. Network use counts as
distribution: run a modified `cm` as a service and you must offer its users the source. See
[`LICENSE`](LICENSE) for the exact terms.

The name and logo are trademarks of Ebsilon, Inc., covered separately by the
[trademark policy](TRADEMARK.md): the code is yours to build on under the AGPL, but
"computermoney" as a product name is not. Contributions require a Developer Certificate of
Origin sign-off (see [`CONTRIBUTING.md`](CONTRIBUTING.md)).

Third-party components (all permissive) are listed in
[`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md).
