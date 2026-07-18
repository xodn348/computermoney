---
title: Home
nav_order: 1
---

# computermoney

> Money that computers use. Bitcoin-native payments between AI agents.

`cm` is a self-custodial **Bitcoin L1 (mainnet)** wallet that an AI agent runs itself. Each
agent holds its own seed and pays other agents in real bitcoin, one Taproot transaction per
payment. No account, no API key, no payment processor. A peer is addressed by its cryptographic
card key, and a payee that publishes a static silent-payment code can be paid while fully
offline.

## The pipeline

Three layers, each doing one job:

1. **Discover — Mainline DHT.** A peer *is* its card key. `cm` publishes a signed card (sp code
   + endpoints) to the DHT, and anyone with the key resolves it. No central directory.
2. **Talk — WireGuard.** For live exchanges, a tunnel keyed by the same seed carries messages
   only, never coins. The offline path skips it.
3. **Settle — Bitcoin L1.** One Taproot transaction per payment. The chain, not any message, is
   the source of truth. Silent Payments give a fresh address per payment from one static code.

`cm` can also **sell and buy data over HTTP 402**: a seller serves a body behind a 402 carrying
its sp code, and a buyer pays it on-chain and gets the content back.

## Pages

- [Payment flow](payment-flow.md) — the function-by-function order inside a single payment.
- [MCP usage](mcp-usage.md) — driving the wallet in plain language over MCP.
- [Try it (2 terminals)](demo-2-terminal.md) — run the full pipeline on one machine.
- [Demo video script](demo-video-script.md) — a shot list for the 2-minute demo.

## For AI agents

An AI-readable map of this site lives at [`llms.txt`](llms.txt), with the full docs inlined in
[`llms-full.txt`](llms-full.txt).

## Source

Code, install, and the full README: [github.com/xodn348/computermoney](https://github.com/xodn348/computermoney).
