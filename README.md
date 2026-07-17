# computermoney

> Money that computers use. **Bitcoin-native autonomous payments between AI agents.**

Two terminal-resident agents (Claude Code / Codex as the engine) hold cryptographic
identities and pay each other in Bitcoin, settling on Bitcoin L1 (Taproot): one chain
transaction per payment, no channels. A payee publishes one static **silent-payment code**
(BIP-352) and can then receive while fully offline; a WireGuard tunnel remains as the
rail for live interaction. The trust model is unchanged: **the key is the identity,
not the IP.**

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/xodn348/computermoney/main/install.sh | sh
```

One line takes a fresh machine to a working payment agent. It builds and installs the **`cm`**
binary from source (needs a [Rust toolchain](https://rustup.rs) and a C compiler), and — if
**Claude Code** is detected — registers the **`cm mcp`** server on a throwaway **signet** demo
wallet, with **zero secrets to type**. Restart Claude Code and say *"send 5000 sats to …"*;
fund the printed signet address from the [faucet](https://faucet.mutinynet.com/).

No-script equivalent (binary only):
`cargo install --git https://github.com/xodn348/computermoney --bin cm`.
**Mainnet** (real BTC) is never auto-wired — seal a seed and set a spend cap, then register with
`CM_NETWORK=mainnet`; see [MCP server](#mcp-server--natural-language-payments).

## What `cm` is

`cm` is **an agent-operated, self-custodial Bitcoin L1 wallet.** Each agent runs its
own `cm`, holds its own seed, and controls its own coins — there is no custodian, no
escrow, no third party that ever holds the counterparty's funds.

It is a *wallet*, not a new payment protocol. What makes it different from a human's
wallet is that a **program** runs it unattended, so it carries the machinery a person
would otherwise supply by hand:

- **one seed → every key** (*key is identity*): the same mnemonic derives
  the Bitcoin keys *and* the WireGuard tunnel key;
- a **signed, append-only ledger** that is the agent's memory (balance, next address,
  in-flight payments) and its crash-recovery substrate;
- **reconciliation**: it trusts the *chain*, not the peer's message, for whether money
  actually arrived;
- a **policy gate** (spend limits, fee cap, address blocklist) the agent cannot talk
  its way around.

## Key genesis: one seed, every key

Every key is drawn locally — no server, no registrar, no Bitcoin Core. The only
randomness is a single 128-bit draw from the OS CSPRNG; everything after it is
deterministic.

```
  OS CSPRNG  (getrandom — macOS or Linux)        the only entropy — 128 bits, local, offline
       │
  12-word mnemonic  ──PBKDF2-HMAC-SHA512──▶  512-bit seed  ──▶  master Xpriv (BIP-32)
                                                                      │  BIP-86 branches
       ├── m/86'/c'/0'/0/n  →  Taproot receive address    (secp256k1) │
       ├── m/86'/c'/0'/1/n  →  Taproot change address     (secp256k1) │
       ├── m/86'/c'/0'/2/0  →  Schnorr ledger-signing key (secp256k1) │
       ├── m/86'/c'/0'/3/0  →  network identity: WireGuard (X25519)   │
       │                       + DHT card key (ed25519), one seed     │
       ├── m/352'/c'/0'/1'/0 → silent-payment scan key    (secp256k1) │
       └── m/352'/c'/0'/0'/0 → silent-payment spend key   (secp256k1) ┘
```

A Bitcoin address is *derived*, never *issued*: it is just an encoding of a public key,
and the network validates the resulting script and signature — not the act of generating
the address. Receiving needs no registration; spending needs only the key.

**The money key and the tunnel key are different cryptographic schemes, joined only at the
seed.** Bitcoin keys live on **secp256k1** and are used to *sign* (Schnorr, BIP-340); the
WireGuard key lives on **Curve25519 / X25519** and is used for *key agreement* (ECDH in the
Noise handshake). The two are not mathematically related — neither public key reveals the
other. What links them is shared *origin*, not shared math: branch 3 derives a 32-byte
BIP-32 child, and `cm` reuses those raw 32 bytes as the X25519 secret (secp256k1 reduces
them mod the curve order; X25519 clamps them — same source bytes, each scheme on its own
curve). The master seed exists first; the Bitcoin and WireGuard keys are equal-rank siblings
derived from it on demand. (This cross-domain reuse is pragmatic, not textbook — strict
domain separation would derive the tunnel key through its own hardened path or KDF.)

## Why the key is safe

The key *is* the identity, so the security of everything — funds, tunnel,
ledger — reduces to one question: can anyone produce your key without your seed? They
cannot, and the reason is two independent walls, each ≈ **2¹²⁸** work.

**Where the secret comes from.** The whole secret is the **128 bits** drawn once from the
operating system's CSPRNG — `getentropy(2)` on macOS, `getrandom(2)` on Linux (both behind Rust's
`getrandom`) — which seeds the 12-word mnemonic (12 words = 128 bits of entropy + a 4-bit checksum). That draw
is **local and offline**: no server issues it, no registrar records it, nothing crosses
the network. There is nothing to intercept, because the secret never leaves the machine
that generated it.

Everything after that draw is **deterministic and public**. BIP-39, BIP-32, and BIP-86
are open standards — an attacker knows the exact algorithm. Security therefore rests not
on hiding the method but on two hard problems:

| Attack | What it takes | Cost |
|---|---|---|
| **Guess the seed** | brute-force the 128-bit entropy | **2¹²⁸** tries |
| **Recover a key from a published address** | solve the elliptic-curve discrete log on secp256k1 (Pollard's rho ≈ √n, n ≈ 2²⁵⁶) | **≈ 2¹²⁸** operations |

Both walls are the same height. **2¹²⁸ ≈ 3.4 × 10³⁸.** Point the entire Bitcoin mining
network — the largest computation humanity has ever aimed at one problem, on the order of
10²¹ hashes per second — at a single key, and covering that space once would take roughly
**10¹⁰ years**, about the present age of the universe. This is not an engineering limit
that faster chips erode; it is an energy wall, and there is no known classical shortcut.
(Honest caveat: a future large-scale *quantum* computer would break the discrete-log wall
via Shor's algorithm and halve the brute-force wall via Grover's — a Bitcoin-wide concern,
not specific to `cm`, and one no fielded machine can do today.)

**So the only real attack surface is the entropy source, not the cryptography.** Because
2¹²⁸ is computationally out of reach, a rational attacker never touches the cipher — they
attack the *input*. If that OS RNG ever returns predictable bytes, the 128-bit wall
collapses: not because the math failed, but because the randomness was never there. That
makes the trust boundary explicit — **`cm`'s keys are exactly as strong as the OS-and-
hardware RNG that Apple and Linux engineer.** Subverting a key means subverting either

- the **kernel CSPRNG** — Apple's XNU random subsystem (Secure Enclave TRNG on Apple Silicon), or the
  Linux kernel RNG and its entropy pool; or
- the **hardware entropy source** itself — the CPU's `RDRAND`/`RDSEED` on Intel/AMD, or
  the on-die true-random generator on Apple Silicon.

That is a hardware- and kernel-engineering attack, not a cryptographic one. History
confirms this is where real keys actually break: the **Debian OpenSSL flaw (2008)** shrank
the key space to ~32,767 values by crippling the entropy pool while leaving the cipher
untouched; an **Android `SecureRandom` flaw (2013)** drained real Bitcoin wallets through
predictable signing nonces; and the Linux kernel deliberately refuses to *trust `RDRAND`
alone*, mixing it with other sources precisely because one hardware RNG is a backdoorable
single point. `cm` inherits that lesson: the cipher is settled — guard the entropy.

## Paying an offline peer: Silent Payments (BIP-352)

The primary rail. The payee's **sp code** (`sp1…`/`tsp1…`) encodes two public keys and
never changes, so it can sit in a chat message, a document, a DHT card, or an HTTP 402
response forever. Paying it needs nothing from the payee:

1. **The payer derives a one-time Taproot address itself**, from its own transaction
   inputs plus the code (ECDH against the payee's scan key). On-chain the result is an
   ordinary P2TR payment; no third party can link it to the code.
2. **The payee scans later.** Whenever it comes back online, `cm_collections` (or a plain
   `cm_balance`, which scans as part of reporting) walks the chain from its checkpoint,
   recognizes its own outputs with the scan key, and books each one in the signed ledger
   together with its key tweak.
3. **The income spends like any other funds.** The spend key for a received output is
   `spend_key + tweak`; every send path (`cm_pay`, `cm_send`, `cm_fetch`) mixes such
   outputs with ordinary wallet funds in one transaction, so money earned by silent
   payment pays an sp code or an HTTP-402 endpoint just as it pays a plain address.

The payee never ran a server, never handed out an address, and never reused one.
Address reuse is what silent payments were designed to kill: one public code, a fresh
address per payment, and only the holder of the scan key can even see the payments.

## Selling over HTTP 402

`cm_paywall` turns a price and a body into a URL. Any GET without payment gets:

```
HTTP/1.1 402 Payment Required
{"cm402":1,"sats":500,"pay_to":"tsp1…","network":"signet"}
```

The buyer's `cm_fetch` reads the terms, pays the sp code on-chain within its cap, and
retries with `X-Payment: <txid>`. The seller verifies by scanning that transaction with
its own scan key (amount must cover the price, each txid redeemable once) and returns
the content. The payment terms travel inside the protocol; no human hands keys around.
This v1 proof is demo-grade by design: a bare txid, accepted at 0 confirmations. Signed
quotes and payer proofs are specified for v2.

## Interactive payments: WireGuard ↔ `cm` ↔ Bitcoin L1

The reserve rail, for when both agents are online and want a live exchange (the payee
issues a fresh address over the tunnel and acknowledges receipt). Two layers,
deliberately never mixed: **WireGuard moves *messages*, Bitcoin L1 moves
*money*, and `cm` is the bridge that turns one into the other.** WireGuard never sees a
coin or touches a Bitcoin key, and the chain — not any peer's message — is the source of
truth for whether money actually arrived.

Agent A pays Agent B over two independent network paths: the WireGuard tunnel *between the
agents* (works on a LAN or localhost — no internet required) and *each agent's own link to
the Bitcoin network* (required to actually settle).

```
   Agent A (payer)                                      Agent B (payee)
   seed → keys (local)                                  seed → keys (local)
        │                                                    │
 ╔══════╪═══════════ WireGuard tunnel (path 1) ══════════════╪══════╗  no internet needed
 ║      │   boringtun Noise_IK, keyed by the branch-3 key     │      ║  (LAN / localhost ok)
 ║      │  (1) AddrRequest{sats}  ───────────────────────▶    │      ║  messages only —
 ║      │  ◀─────────────────── (2) AddrResponse{addr, idx}   │  (2) B derives a
 ║      │  (4) Notify{txid, sats} ──────────────────────▶     │      fresh address locally
 ╚══════╪═════════════════════════════════════════════════════╪══════╝
        │                                                     │
   (3) policy → build → Schnorr-sign → broadcast        (5) reconcile: query confirmations
        │                                                     │
 ━━━━━━━╪━━━━━━━━━━━ Bitcoin L1 (path 2) ━━━━━━━━━━━━━━━━━━━━━━╪━━━━━  internet required
        ▼  broadcast via esplora                              ▼  query via esplora
   ┌────────────────── Bitcoin network (global consensus) ──────────────────┐
   │  every node (Bitcoin Core included) validates the tx under the same    │
   │  rules and agrees independently.  0 / 1 / 3 confs = Pending/Soft/Final  │
   └────────────────────────────────────────────────────────────────────────┘
        │  each side records the result in its own Schnorr-signed ledger file
```

1. **A asks for an address.** A opens the tunnel to B's WireGuard public key (Noise_IK,
   branch-3 key) and sends `AddrRequest{sats}`. *Path 1 — UDP between the agents; no internet.*
2. **B derives a fresh address locally.** A new BIP-86 Taproot address at `m/86'/.../0/n`,
   computed on the spot (no node, no registration), returned as `AddrResponse{addr, idx}`
   and recorded as *issued* in the ledger. *Offline.*
3. **A settles on-chain.** A runs the policy gate (limits, fee cap, blocklist), builds the
   tx, **Schnorr-signs** it, and **broadcasts** it. Signing is offline; the broadcast must
   reach a Bitcoin node. *Path 2 — internet required.*
4. **A notifies.** `Notify{txid, sats}` over the tunnel — a hint, not proof. *Path 1.*
5. **B verifies on-chain, then reconciles.** The `Notify` is only a trigger: B queries the
   chain for the deposit to the address it issued and books the **real** output value (never
   the claimed one), then `reconcile` advances it by confirmations; 3 confs = Final. Global
   consensus validates the tx — B's standard BIP-86 address is honored by every node, Bitcoin
   Core included. *Internet required.*
6. **Both record it** in their own signed append-only `ledger.jsonl`, inside each agent's
   identity directory (balance, work queue, crash recovery).

**Where trust sits.** A `Notify` is never trusted: the receive side does **not** credit the
amount the payer claims. It looks the transaction up on-chain against the address it issued
and books the **real** output value the chain reports — or nothing, if the tx is not visible
yet, in which case the seller daemon's chain-watch books it once it lands. So a hostile payer
naming any confirmed txid, or inflating the amount, credits nothing: the chain is the sole
source of receipt and the message is only a low-trust trigger.

**One honest gap remains.** The *decision* to pay — the trigger for step 1 — lives outside
`cm` today (a human, or an agent that execs `cm pay` / calls the `cm_pay` MCP tool); the
seller's `cm serve` is an unattended daemon, so `cm` is the autonomous *hands*, not yet the
*brain*.

> **Wire-level detail:** [`docs/payment-flow.md`](docs/payment-flow.md) walks through the
> exact function-by-function order inside `cm pay` and the seller daemon — the two stacked
> handshakes, where `InvalidMac` comes from, and the message framing.

## Network status

- **Default — Bitcoin L1 mainnet.** Real BTC, out of the box. Key derivation matches the
  BIP-86 mainnet test vectors, and broadcasts use the network's recommended feerate
  (esplora fee estimates, with a conservative floor). Honest remaining gaps: no RBF/CPFP
  fee-bumping yet (a tx stuck behind a fee spike can't be re-fee'd from `cm`), and the
  default esplora endpoint is public (point `CM_ESPLORA` at your own for privacy/trust).
- **Testing — testnet / signet.** Set `CM_NETWORK=testnet` or `CM_NETWORK=signet` to run
  the exact same code path with worthless coins. Signet defaults to a 30-second-block
  endpoint, so 3-confirmation *Final* is ~90 s — this is what the demo uses.
- **Planned — L2 Lightning.** Not built; under consideration only.

## v1 boundaries (stated, not hidden)

- **The scanner sees payments whose inputs are P2TR key-path or P2WPKH only.** cm's own
  payments always qualify. An external wallet that mixes in other input types (P2PKH,
  P2SH-P2WPKH) produces a payment the v1 scanner cannot recognize; a spec-complete
  scan tier is the mainnet milestone.
- **Silent-payment sends have a 330-sat minimum**, matching the receiver dust floor, so
  nothing cm sends can arrive unseen.
- **The paywall accepts a bare txid at 0 confirmations.** Fine for small per-call prices;
  the v2 spec adds signed quotes, payer proofs, and confirmation floors.
- **No reorg rescan.** A payment reorged out from under the scan checkpoint stays
  Pending and is not rediscovered automatically.

## Platforms

`cm` runs on **macOS and Linux**. The code has no platform-specific branches — the same
Rust builds on both — so what differs is OS-internal and changes neither behaviour nor
security:

| | macOS | Linux |
|---|---|---|
| Entropy syscall (the 128-bit seed draw) | `getentropy(2)` | `getrandom(2)` |
| Kernel CSPRNG behind it | XNU random (Secure Enclave TRNG on Apple Silicon) | kernel RNG + entropy pool |
| Config directory | `~/.config/computermoney/` | `~/.config/computermoney/` |
| Tunnel transport | `std::net` UDP | `std::net` UDP |
| Build prerequisite | C toolchain (Xcode CLT / clang) | C toolchain (gcc / cc) |

Both entropy syscalls feed Rust's `getrandom` and are equally a CSPRNG, so the security
argument above holds identically on either OS. CI builds and tests both on every push.
Windows is not supported for now (it builds, but `ring` needs `nasm` there).

## Commands

The surface is the pipeline: **discover** (Mainline DHT) → **talk** (WireGuard) →
**settle** (Bitcoin L1). A peer *is* its card key — `cm pay <card-key> <sats>` is
the whole thing.

```
cm setup                          create a wallet, then show identity, sp code, fund address, balance
cm id                             print your card key and static sp code — the handles you share
cm publish [host:port ...]        sign + put your card (sp code, endpoints) to the DHT yourself
cm serve [--bind a] [--ep a]...   run the seller daemon: publish, accept buyers, watch the chain
cm pay <sp-code> <sats>           pay a silent-payment code on-chain (payee may be offline)
cm pay <card-key> <sats>          discover -> talk -> settle, in one command
cm pay <pubkey@host:port> <sats>  pay a known endpoint directly (no DHT)
cm fetch <url> [--max-sats N]     GET a URL, auto-paying a cm HTTP 402 within the cap
cm paywall <price> [--port N] [--body S]  sell one body over HTTP 402 (blocking foreground)
cm balance                        sync from the chain, print on-chain + silent-payment balance
cm confs <txid>                   confirmation count + status (pending/soft/final)
cm mcp                            stdio MCP server for AI-agent clients (tools below)
```

The buyer needs nothing running — `cm pay` (or the `cm_pay` MCP tool) does discover →
talk → settle in one shot. The seller runs one resident process, `cm serve`, which
republishes its DHT card before it expires, answers any buyer's WireGuard handshake (the
buyer's key is learned from the handshake, not configured), and polls the chain so a
payment is recorded even if no tunnel was live when it landed. `--ep` is the endpoint
published on the card (repeatable for a v4 + v6 pair); omit it to stay dial-out only.
Publishing an endpoint exposes that IP to every card-key holder, so publish a hop/VPS
address, not your home IP, or none.

Wallet unlock: an encrypted seed (`CM_PASSPHRASE`) or the stored mnemonic; `CM_MNEMONIC`
overrides both.
Network: `CM_NETWORK` = `mainnet` (default) | `testnet` | `signet`; `CM_ESPLORA` overrides
the esplora endpoint.

**Identities.** `cm setup` creates one agent, stored in its own directory
`~/.config/computermoney/<id8>/` — the first 8 hex chars of its WireGuard identity —
holding that agent's `mnemonic` (or `seed.enc`) and `ledger.jsonl`. So two agents on one
machine never share, or cross-sign, a ledger. With several wallets in the store, the acting
identity is chosen by `CM_ID=<id prefix>`, or the `default` marker (the first identity
created), or — with only one wallet — automatically. `policy.json` stays at the config root
(global; `CM_POLICY` overrides).

## Two agents on signet, end to end

Run a seller and a buyer as two separate identities on one machine (`CM_HOME` gives each its
own wallet store) and watch the whole pipeline — discover, talk, settle — move real signet
coins. Everything is signet, so nothing here spends mainnet BTC.

The offline flow needs no daemon at all:

```sh
export CM_NETWORK=signet
CM_HOME=~/cm-seller cm setup                  # prints B's sp code; card goes to the DHT
# B can now shut everything down.
CM_HOME=~/cm-buyer  cm pay <B-sp-code> 1000   # or <B-card-key>: resolves the card, pays on-chain
# Later, B returns and collects (the cm_collections MCP tool scans to tip and books it),
# then spends the income like any other funds.
```

The interactive flow runs the resident daemon:

```sh
# --- Seller (agent B): its own store, its own wallet, a resident daemon ---
export CM_NETWORK=signet
CM_HOME=~/cm-seller cm setup                 # prints B's card key + a funding address
CM_HOME=~/cm-seller cm serve --bind 0.0.0.0:51820 --ep <seller-host>:51820
#   -> publishes B's card to the DHT, then waits, republishing every 45 min and
#      polling the chain. On localhost use --bind 127.0.0.1:51820 --ep 127.0.0.1:51820.

# --- Buyer (agent A): a different store, fund it from the signet faucet once ---
CM_HOME=~/cm-buyer  cm setup                  # prints A's funding address
#   fund that address at https://faucet.mutinynet.com/ , wait one block, then:
CM_HOME=~/cm-buyer  cm pay <B-card-key> 5000  # discover -> talk -> settle, one command
```

What happens, in order: A resolves B's card key on the DHT to B's endpoint, opens a WireGuard
tunnel to it, asks for a fresh address over that tunnel, broadcasts a 5000-sat signet payment
to it, and tells B the txid. B's daemon issues the address, records the incoming payment, and
its chain-watch advances it to final once it confirms — no listener had to be armed in
advance. Check either side any time with `CM_HOME=… cm balance`, and on the seller list every
collection with the `cm_collections` MCP tool. Swap `cm pay` for the `cm_pay` MCP tool and the
same flow runs from *"pay 5000 sats to `<B-card-key>`"* in an MCP client, with no shell.

## MCP server — natural-language payments

`cm mcp` runs `cm` as a **[Model Context Protocol](https://modelcontextprotocol.io) server**
over stdio, so any MCP client (Claude Code, Claude Desktop, or your own agent) can drive the
whole pipeline from a plain instruction — *"pay 5000 sats to `<card-key>`"* — with no shell, no
flags, no key handling. It exposes exactly these tools and nothing else:

| Tool | Arguments | What it does |
|---|---|---|
| `cm_setup` | *(none)* | create the wallet if absent and report network, card key, sp code, address, balance; safe to call anytime |
| `cm_pay` | `peer` (sp code, 64-hex card key, or `wg-pubkey@host:port`), `sats` (integer ≥ 1) | the flagship verb: pay by sp code (on-chain, payee may be offline), by card key (DHT), or a direct link; returns the txid + explorer URL |
| `cm_send` | `address` (string), `sats` (integer ≥ 1) | on-chain send to an address you hold, drawing on received silent-payment funds too; returns the txid + explorer URL |
| `cm_fetch` | `url` (string), `max_sats` (integer, default 10000) | GET a URL and auto-pay a cm HTTP 402 within the cap; returns the body plus the sats paid + txid when a payment happened |
| `cm_paywall` | `price_sats` (integer ≥ 1), `body` (string, optional), `port` (integer, default 8402) | sell one body over HTTP 402 for the session; returns the URL whose 402 carries your sp code |
| `cm_balance` | *(none)* | confirmed + pending on-chain balance plus silent-payment income; scans the chain for offline SP income on every call and also shows income received but not yet spendable, so a plain balance check reflects money paid while you were away |
| `cm_collections` | *(none)* | scan the chain and report every received payment as itemized rows, including offline silent-payment income |
| `cm_confs` | `txid` (string) | a payment's confirmation count + status (pending/soft/final), and advances the ledger |
| `cm_id` | *(none)* | print your card key and static sp code — the payee handles you share |
| `cm_address` | *(none)* | the wallet's on-chain funding address (receive index 0) |
| `cm_serve` | `bind` (optional), `ep` (optional) | run the interactive seller daemon in the background for the session; endpoint auto-detected |

`cm_pay` and `cm_send` are the same ledger-first path `cm pay` settles through: the agent supplies
only `{card_key/address, sats}` — **the seed and passphrase are never tool arguments.** The wallet
is unlocked **once** at startup (a single KDF pass) and held for the process lifetime, so each call
is fast and the secret never crosses the tool boundary. Startup also reconciles the ledger, so a
payment that confirmed while the client was away is healed on the next session.

The [installer](#install) already does this for Claude Code on a signet demo wallet. To wire it
**manually** — Claude Desktop, another client, or mainnet — point your MCP config (`.mcp.json`
or `claude_desktop_config.json`) at the `cm` binary with `mcp`, plus the network in the env.
The registration carries **no secret**: the server resolves the identity from the store on
disk (run `cm setup` first). Signet demo:

```json
{
  "mcpServers": {
    "computermoney": {
      "command": "/abs/path/to/cm",
      "args": ["mcp"],
      "env": {
        "CM_NETWORK": "signet"
      }
    }
  }
}
```

Add `"CM_ID": "<id8>"` only if the machine holds several identities and you want a specific
one; otherwise the `default` (or sole) identity is used.

For **mainnet** (real BTC), unlock the sealed seed with a passphrase instead of a plaintext
mnemonic, and **set a spend cap** — on mainnet `cm` refuses to broadcast unless `policy.json`
carries an effective limit (`max_payment_sats` or `daily_limit_sats`):

```json
"env": {
  "CM_NETWORK": "mainnet",
  "CM_PASSPHRASE": "<passphrase that seals seed.enc>",
  "CM_POLICY": "/abs/path/to/policy.json"
}
```

```json
// policy.json — limits the agent cannot talk its way around
{ "max_payment_sats": 50000, "daily_limit_sats": 200000 }
```

That mainnet cap is **fail-closed**: an absent or empty policy means *unlimited*, so on mainnet
a cap-less send is rejected before any signing — a guard the agent can't bypass because it sits
at the single on-chain chokepoint (`chain::send`) every send path funnels through.
Signet/testnet stay permissive for the demo. The server speaks JSON-RPC 2.0 on **stdout only**;
all diagnostics go to stderr, so the stream stays clean for the client.

## License

**[MIT License](LICENSE)**, Copyright 2026 Junhyuk Lee. Permissive: use, modify,
and redistribute it, including in commercial and closed-source products, as long as
the copyright notice travels with it. See [`LICENSE`](LICENSE) for the exact terms.

The name and logo are covered separately by the [trademark policy](TRADEMARK.md):
the code is yours to build on, but "computermoney" as a product name is not.
Contributions require a Developer Certificate of Origin sign-off (see
[`CONTRIBUTING.md`](CONTRIBUTING.md)).

computermoney bundles third-party open-source components (all permissive:
MIT / Apache-2.0 / BSD / ISC / CC0, plus MPL-2.0 for `webpki-roots`), none of
which impose a copyleft obligation on this source. Full attributions and license
texts are in [`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md).
