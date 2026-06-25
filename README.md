# computermoney

> Money that computers use. **Bitcoin-native autonomous payments between AI agents.**

Two terminal-resident agents (Claude Code / Codex as the engine) hold cryptographic
identities and pay each other in Bitcoin. They coordinate over a WireGuard tunnel and
settle on Bitcoin L1 (Taproot) — one chain transaction per payment, no channels. The
trust model is WireGuard's: **the key is the identity, not the IP.**

The binary is `cm`. This repo holds the working v1 implementation (`src/`).

## What `cm` is

`cm` is **an agent-operated, self-custodial Bitcoin L1 wallet.** Each agent runs its
own `cm`, holds its own seed, and controls its own coins — there is no custodian, no
escrow, no third party that ever holds the counterparty's funds.

It is a *wallet*, not a new payment protocol. What makes it different from a human's
wallet is that a **program** runs it unattended, so it carries the machinery a person
would otherwise supply by hand:

- **one seed → every key** (Pillar 1, *key is identity*): the same mnemonic derives
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
  OS CSPRNG  (getentropy on macOS)        the only entropy — 128 bits, local, offline
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

The key *is* the identity (Pillar 1), so the security of everything — funds, tunnel,
ledger — reduces to one question: can anyone produce your key without your seed? They
cannot, and the reason is two independent walls, each ≈ **2¹²⁸** work.

**Where the secret comes from.** The whole secret is the **128 bits** drawn once from the
operating system's CSPRNG — `getentropy(2)` on macOS, `getrandom(2)` on Linux — which
seeds the 12-word mnemonic (12 words = 128 bits of entropy + a 4-bit checksum). That draw
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
attack the *input*. If `getentropy` ever returns predictable bytes, the 128-bit wall
collapses: not because the math failed, but because the randomness was never there. That
makes the trust boundary explicit — **`cm`'s keys are exactly as strong as the OS-and-
hardware RNG that Apple and Linux engineer.** Subverting a key means subverting either

- the **kernel CSPRNG** — Apple's XNU random subsystem (seeded by the Secure Enclave's
  hardware TRNG on Apple Silicon), or the Linux kernel RNG and its entropy pool; or
- the **hardware entropy source** itself — the CPU's `RDRAND`/`RDSEED` on Intel/AMD, or
  the on-die true-random generator on Apple Silicon.

That is a hardware- and kernel-engineering attack, not a cryptographic one. History
confirms this is where real keys actually break: the **Debian OpenSSL flaw (2008)** shrank
the key space to ~32,767 values by crippling the entropy pool while leaving the cipher
untouched; an **Android `SecureRandom` flaw (2013)** drained real Bitcoin wallets through
predictable signing nonces; and the Linux kernel deliberately refuses to *trust `RDRAND`
alone*, mixing it with other sources precisely because one hardware RNG is a backdoorable
single point. `cm` inherits that lesson: the cipher is settled — guard the entropy.

## Architecture: WireGuard ↔ `cm` ↔ Bitcoin L1

Two separate things, deliberately never mixed. WireGuard moves *messages*; Bitcoin L1
moves *money*; `cm` is the bridge that turns one into the other.

```
        Agent A  (cm)                                   Agent B  (cm)
            │                                               │
            │ ════════════  WireGuard tunnel  ════════════  │   COORDINATION
            │   AddrRequest{sats} ───────────────────────▶  │   messages only,
            │   ◀─────────────────────── AddrResponse{addr} │   no money here
            │   Notify{txid} ───────────────────────────▶   │
            │                                               │
   cm: take addr, run policy,                      cm: issue a fresh Taproot
   build + sign + broadcast a tx                   address, record it, then
            │                                      reconcile against the chain
            ▼  broadcast signed transaction                 ▲  query confirmations
   ════════════════════════  Bitcoin L1 (Taproot/P2TR)  ════════════════════════
            the only place value moves — and the only source of truth          SETTLEMENT
```

**Where WireGuard stops.** WireGuard's job is to encrypt, authenticate, and deliver a
message to the right peer (Noise handshake keyed by the seed-derived X25519 key, over
UDP). It never sees a coin and never touches a Bitcoin key. Its responsibility ends the
moment the bytes reach the peer. The messages it carries are tiny: *ask for an address*,
*here is an address*, *I broadcast this txid*. (The address could travel over any
channel — WireGuard is simply the private, authenticated line the agents already share.)

**Where Bitcoin L1 begins.** L1's job starts when `cm` broadcasts a signed transaction.
The chain records the transfer and confirms it; the chain — not any message — is the
source of truth for money. A `Notify` is only a latency hint.

**What `cm` does in between (the whole product).** `cm` is everything between the two
layers:

| On the **pay** side | On the **receive** side |
|---|---|
| check policy (per-payment + daily limit) *before* contacting the peer | answer `AddrRequest` with a **fresh** Taproot address (rotating BIP-86 index, no reuse) |
| read the address out of the WireGuard message | record the issuance in the signed ledger |
| check the blocklist now that the destination is known | record the incoming `Notify` as *pending* |
| sync UTXOs, **build + sign** a P2TR tx, enforce the fee cap, **broadcast** to L1 | **reconcile** the txid against the chain: 0 / 1 / 3 confs = Pending / Soft / Final |
| record the `Sent` entry *before* notifying (crash-safe) | count only *Final* money as spendable balance |

So a message carrying an address (WireGuard) becomes a signed transaction (L1) and then
a confirmed balance (ledger) — and `cm` performs every one of those translations.

### Source layout

| Module | Role |
|---|---|
| `src/wallet.rs` | seed → keys: BIP-86 Taproot addresses, Schnorr ledger key, X25519 WG key |
| `src/storage.rs` | encrypted seed at rest (Argon2id + ChaCha20-Poly1305); config paths |
| `src/chain.rs` | Bitcoin L1 via `bdk` + esplora: balance, build/sign/broadcast, confirmations |
| `src/ledger.rs` | signed append-only ledger (the agent's memory) + `reconcile` |
| `src/protocol.rs` | the wire messages: `AddrRequest` / `AddrResponse` / `Notify` / `Chat` |
| `src/net.rs` | transport-agnostic payment protocol (the `Wire` seam) |
| `src/tunnel.rs` | WireGuard transport (`boringtun`), seed-derived WG identity |
| `src/policy.rs` | spend limits, fee cap, address blocklist |

## End-to-end: the life of one payment

Agent A pays Agent B. Two independent network paths are in play: the WireGuard tunnel
*between the agents* (works on a LAN or localhost — no internet required) and *each agent's
own link to the Bitcoin network* (required to actually settle).

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
        │  each side records the result in its own Schnorr-signed ledger.jsonl
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
6. **Both record it** in their own signed append-only `ledger.jsonl` (balance, work queue,
   crash recovery).

**Two honest gaps.** (1) The *decision* to pay — the trigger for step 1 — lives outside
`cm` today (a human, or an agent that execs `cm pay`); `cm receive` is already an unattended
daemon, so `cm` is the autonomous *hands*, not yet the *brain*. (2) Step 5 is incomplete:
`reconcile` confirms the txid is buried but does **not** yet verify the transaction pays B's
issued address for the claimed amount, so a lying `Notify` can record a phantom credit — the
top correctness fix is to verify the on-chain output inside `reconcile`.

## Network status

- **Now — Bitcoin L1 testnet only.** Settlement runs on **mutinynet** (a 30-second-block
  signet), so 3-confirmation *Final* is ~90 s. It is real on-chain settlement with real
  Taproot, real keys, and a real signed/broadcast transaction — only the coins are
  worthless. Endpoint and `Network::Signet` are currently hardcoded in `src/chain.rs`.
- **Planned — Bitcoin L1 mainnet.** Real BTC. Key derivation already matches the BIP-86
  mainnet test vectors, but mainnet needs explicit fee control (feerate + RBF/CPFP), a
  trusted/own esplora or node backend, and real-value testing first. Not yet built.
- **Planned — L2 Lightning.** Not built; under consideration only.

## Commands

WireGuard is the transport, so the surface is two verbs: `receive` and `pay`. A
peer *is* its public key — `cm pay <pubkey>@<host:port> <sats>` is the whole thing.

```
cm init                           create a wallet (seals the seed if CM_PASSPHRASE is set)
cm id                             print your identity — the pubkey a peer pays to
cm receive <payer-pubkey> [bind]  wait for a payment over WireGuard (bind 0.0.0.0:51820)
cm pay <pubkey@host:port> <sats>  pay a peer over WireGuard

cm balance                        sync from the chain, print balance
cm address [n]                    a receive address (to fund the wallet)
cm send <addr> <sats>             raw on-chain send to an address (policy-gated)
cm confs <txid>                   confirmation count for a txid
cm policy                         show the active spend policy (limits / fee / blocklist)
cm demo [sats]                    full end-to-end payment flow in one process
```

Wallet unlock: an encrypted seed (`CM_PASSPHRASE`) or `CM_MNEMONIC` for the demo.
Config lives under `~/.config/computermoney/` (`seed.enc`, `ledger.jsonl`,
`policy.json`); override with `CM_SEED` / `CM_LEDGER` / `CM_POLICY`.

## License

Source-available under the **[PolyForm Shield License 1.0.0](LICENSE)** —
Copyright 2026 Junhyuk Lee. Use it for anything, including building products on
top of it; the one carve-out is that you may not use it to build a product that
competes with computermoney. See [`LICENSE`](LICENSE) for the exact terms.
