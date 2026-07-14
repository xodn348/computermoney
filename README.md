# computermoney

> Money that computers use. **Bitcoin-native autonomous payments between AI agents.**

Two terminal-resident agents (Claude Code / Codex as the engine) hold cryptographic
identities and pay each other in Bitcoin. They coordinate over a WireGuard tunnel and
settle on Bitcoin L1 (Taproot) — one chain transaction per payment, no channels. The
trust model is WireGuard's: **the key is the identity, not the IP.**

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
       └── m/86'/c'/0'/3/0  →  WireGuard static key          (X25519) ┘
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

## How a payment works: WireGuard ↔ `cm` ↔ Bitcoin L1

Two layers, deliberately never mixed: **WireGuard moves *messages*, Bitcoin L1 moves
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
5. **B reconciles against the chain.** B trusts the chain, not the message: `reconcile`
   queries confirmations; 3 confs = Final. Global consensus validates the tx — B's standard
   BIP-86 address is honored by every node, Bitcoin Core included. *Internet required.*
6. **Both record it** in their own signed append-only `ledger.jsonl`, inside each agent's
   identity directory (balance, work queue, crash recovery).

**Two honest gaps.** (1) The *decision* to pay — the trigger for step 1 — lives outside
`cm` today (a human, or an agent that execs `cm pay`); `cm receive` is already an unattended
daemon, so `cm` is the autonomous *hands*, not yet the *brain*. (2) Step 5 is incomplete:
`reconcile` confirms the txid is buried but does **not** yet verify the transaction pays B's
issued address for the claimed amount, so a lying `Notify` can record a phantom credit — the
top correctness fix is to verify the on-chain output inside `reconcile`.

> **Wire-level detail:** [`docs/payment-flow.md`](docs/payment-flow.md) walks through the
> exact function-by-function order inside `cm pay` and `cm receive` — the two stacked
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

WireGuard is the transport, so the surface is two verbs: `receive` and `pay`. A
peer *is* its public key — `cm pay <pubkey>@<host:port> <sats>` is the whole thing.

```
cm setup                          create+seal a wallet, then show identity, fund address, balance
cm init                           create a wallet (seals the seed if CM_PASSPHRASE is set)
cm id                             print your identity — the pubkey a peer pays to
cm receive <payer-pubkey> [bind]  wait for a payment over WireGuard (bind 0.0.0.0:51820)
cm pay <pubkey@host:port> <sats>  pay a peer over WireGuard

cm balance                        sync from the chain, print balance
cm address [n]                    a receive address (to fund the wallet)
cm send <addr> <sats>             raw on-chain send to an address (policy-gated)
cm confs <txid>                   confirmation count for a txid
cm policy                         show the active spend policy (limits / fee / blocklist)
cm mcp                            stdio MCP server (cm_send, cm_balance) for AI-agent clients
```

Wallet unlock: an encrypted seed (`CM_PASSPHRASE`) or the stored mnemonic; `CM_MNEMONIC`
overrides both.
Network: `CM_NETWORK` = `mainnet` (default) | `testnet` | `signet`; `CM_ESPLORA` overrides
the esplora endpoint.

**Identities.** Each `cm init` creates one agent, stored in its own directory
`~/.config/computermoney/<id8>/` — where `<id8>` is the first 8 hex chars of the identity
`cm id` prints — holding that agent's `mnemonic` (or `seed.enc`) and `ledger.jsonl`. So two
agents on one machine never share, or cross-sign, a ledger. Run `cm init` twice and you have
two agents. The acting identity is chosen by `CM_ID=<id prefix>`, or the `default` marker
(the first identity created), or — with only one wallet — automatically. `policy.json` stays
at the config root (global; `CM_POLICY` overrides).

## MCP server — natural-language payments

`cm mcp` runs `cm` as a **[Model Context Protocol](https://modelcontextprotocol.io) server**
over stdio, so any MCP client (Claude Code, Claude Desktop, or your own agent) can pay
Bitcoin from a plain instruction — *"send 5000 sats to tb1p…"* — with no shell, no flags, no
key handling. It exposes exactly two tools and nothing else:

| Tool | Arguments | What it does |
|---|---|---|
| `cm_send` | `address` (string), `sats` (integer ≥ 1) | policy-gates, builds, Schnorr-signs, and broadcasts one on-chain payment; returns the txid + explorer URL |
| `cm_balance` | *(none)* | confirmed + pending balance on the active network |

`cm_send` is the same code path as `cm send`: the agent supplies `{address, sats}` and nothing
else — **the seed and passphrase are never tool arguments.** The wallet is unlocked **once** at
startup (a single KDF pass) and held for the process lifetime, so each call is fast and the
secret never crosses the tool boundary.

The [installer](#install) already does this for Claude Code on a signet demo wallet. To wire it
**manually** — Claude Desktop, another client, or mainnet — point your MCP config (`.mcp.json`
or `claude_desktop_config.json`) at the `cm` binary with `mcp`, plus the network in the env.
The registration carries **no secret**: the server resolves the identity from the store on
disk (run `cm init` first). Signet demo:

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

Free software under the **[GNU AGPL-3.0](LICENSE)** (`AGPL-3.0-only`),
Copyright 2026 Ebsilon, Inc. Use it, study it, modify it, redistribute it. The
one condition: if you distribute a modified version, or offer one as a network
service, you must make its complete source available under the same license.
See [`LICENSE`](LICENSE) for the exact terms.

The name **"computermoney"** and the project logo are trademarks and are not
covered by the code license. Unmodified official builds may carry the name;
forks and derivative products must pick a different one. See
[`TRADEMARK.md`](TRADEMARK.md) for the full policy.

computermoney bundles third-party open-source components (all permissive:
MIT / Apache-2.0 / BSD / ISC / CC0, plus MPL-2.0 for `webpki-roots`), none of
which impose a copyleft obligation on this source. Full attributions and license
texts are in [`THIRD-PARTY-LICENSES.md`](THIRD-PARTY-LICENSES.md).
