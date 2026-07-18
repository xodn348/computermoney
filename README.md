# computermoney

> Money that computers use. **Bitcoin-native payments between AI agents.**

## What is `cm`

`cm` is a self-custodial Bitcoin wallet for AI agents. Each agent runs its own `cm`,
holds its own seed, and pays other agents in real bitcoin, settling on Bitcoin L1
(Taproot) with one on-chain transaction per payment. No account, no API key, no payment
processor. **The key is the identity, not the IP:** a peer is addressed by its
cryptographic card key, and a payee that publishes a static silent-payment code can be
paid while fully offline.

## How it works

Three layers, each doing one job: **discover** on the DHT, **talk** over WireGuard,
**settle** on Bitcoin L1.

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

**3. Settle — Bitcoin L1.** Every payment is one Taproot transaction. The chain, not any
peer's message, is the source of truth: the receiver credits the real on-chain output, and
confirmations advance it. Silent Payments ([BIP-352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki))
give the payee a fresh one-time address per payment from one static code, so it can be paid
offline and scan for its income later.

**Also over HTTP 402.** `cm` can sell and buy data directly: a seller serves a body behind an
HTTP 402 response that carries its sp code, and a buyer's `cm fetch` pays it on-chain within a
cap and gets the content back. No signup, no card.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/xodn348/computermoney/main/install.sh | sh
```

Builds and installs the `cm` binary (needs a [Rust toolchain](https://rustup.rs) and a C
compiler), and, if Claude Code is detected, registers the `cm mcp` server on a throwaway
**signet** demo wallet with no secrets to type. Fund the printed signet address from the
[faucet](https://faucet.mutinynet.com/). Mainnet is never auto-wired: seal a seed and set a
spend cap first.

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

- [`docs/payment-flow.md`](docs/payment-flow.md) — the function-by-function order inside `cm pay` and the seller daemon.
- [`docs/mcp-usage.md`](docs/mcp-usage.md) — driving the wallet in plain language over MCP.
- [`docs/demo-2-terminal.md`](docs/demo-2-terminal.md) — two-terminal signet walkthrough (discover → talk → settle).
- [`docs/testnet-2-terminal.md`](docs/testnet-2-terminal.md) — two-agent testnet walkthrough.
- [`docs/demo-video-script.md`](docs/demo-video-script.md) — shot list for the demo video.

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
