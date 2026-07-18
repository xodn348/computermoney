---
title: Payment flow
nav_order: 3
---

This is the wire-level walkthrough of a single payment: what the **sender** and
**receiver** actually do, function by function, in call order. The high-level
picture is in [Architecture](architecture.md); the module/type/CLI index is in
the [Reference](reference.md); driving the same paths from an agent is in
[MCP usage](mcp-usage.md).

A payment settles in one of two shapes, and the sender picks one when it resolves
the peer:

- **Live (tunnel) path.** The two agents are both online. The payer opens a
  WireGuard tunnel, asks the seller for a fresh BIP-86 Taproot address over it,
  and pays that address on-chain. Entry: `cm pay <pubkey>@<host:port>` (direct),
  or `cm pay <card-key>` when the resolved card has endpoints but no sp code.
- **Offline (silent-payment) path.** The payee may be offline. The payer decodes
  the payee's static silent-payment code (BIP-352), derives a one-time Taproot
  output from its own inputs, and broadcasts. No tunnel, no address request, no
  live session. Entry: `cm pay <sp-code>`, or `cm pay <card-key>` when the
  resolved card carries an sp code (the default, since `cm publish` and
  `cm serve` always advertise one).

Both shapes are one Taproot transaction per payment, confirmed by the chain, and
recorded in the same signed ledger. The difference is only *how the destination
address is agreed on*: interactively over WireGuard, or derived offline from a
published code.

Source of truth for the flow below: [`src/main.rs`](../src/main.rs) (dispatch and
peer resolution), [`src/tunnel.rs`](../src/tunnel.rs) (WireGuard transport),
[`src/net.rs`](../src/net.rs) (the transport-agnostic live protocol),
[`src/pay.rs`](../src/pay.rs) (the build → record → broadcast ordering),
[`src/chain.rs`](../src/chain.rs) (bdk + esplora), [`src/sp.rs`](../src/sp.rs)
(BIP-352 math), [`src/scan.rs`](../src/scan.rs) (the receive scanner), and
[`src/ledger.rs`](../src/ledger.rs) (the append-only signed log and reconcile).

## Sender path

### 1. Entry and peer resolution — `main.rs:204`

`cm pay <peer> <sats>` reads the peer handle and amount (`main.rs:211-212`), loads
the wallet (`main.rs:213`), and branches on the *shape* of the handle:

1. **`sp1…` / `tsp1…` prefix** (`main.rs:214`): a silent-payment code. Goes
   straight to `cli_sp_pay` (`main.rs:216`, defined at `main.rs:39`) — the offline
   path, no discovery needed.
2. **`pubkey@host:port`** (`main.rs:219`): a known WireGuard endpoint. Goes to
   `tunnel::pay` (`main.rs:220`) — the live path, no discovery needed.
3. **A bare card key** (`main.rs:222`): resolve it on the DHT. `discover::parse_card_key`
   (`main.rs:222`) then `discover::resolve` (`main.rs:224`, in
   [`discover.rs`](../src/discover.rs)) looks up the peer's signed card. Then:
   - if the card carries an sp code (`main.rs:228`), pay it offline via
     `cli_sp_pay` (`main.rs:230`);
   - otherwise dial each published endpoint in turn via `tunnel::pay`
     (`main.rs:243-245`), failing over from one to the next.

So discovery only feeds the resolved sp code or endpoint into the same two paths
below. Everything after resolution is identical whether the handle came from the
DHT or was passed directly.

### 2a. Live path — `tunnel::pay` → `net::run_payer` → `pay::send`

```
   cm pay <pubkey>@<host:port> (payer A)      cm serve (seller B)
 ═══════════════════════════════════════     ══════════════════════════
 tunnel::pay                                  serve::run
  │ identity() → X25519 secret (branch 3)      │ lock_dir + open signed ledger
  │ bind UDP 0.0.0.0:0                          │ bind UDP :51820, loop:
  │                                             │   REPUBLISH · WATCH · ACCEPT
  │── WireGuard handshake (Noise_IK) ────────────────────────────────────────
  │ FramedTunnel::connect ──(initiation)──────▶ FramedTunnel::accept_any
  │                       ◀──(response)──────── (learns A's key from handshake)
  │ ──(keepalive)─────────────────────────────▶ session ready
  │ "[wg] tunnel established"                   │
  │── every message now sealed inside the tunnel ────────────────────────────
 net::run_payer                               net::run_receiver
  │ check_amount (spend gate)                   │
  │ send AddrRequest{sats} ───────────────────▶ rx.handle → wallet.address(i)
  │                                             │   append AddressIssued{i}
  │ recv ◀── AddrResponse{addr, i} ──────────── send AddrResponse
  │ check_address(addr) (blocklist)             │
  │── settle on Bitcoin L1 (NOT the tunnel) ─────────────────────────────────
  │ pay::send:                                  │
  │   chain::build_signed (sync→build→sign)     │
  │   write_sidecar → append Sent{Pending}      │
  │   chain::broadcast → txid                   │
  │ send Notify{txid, sats} ──────────────────▶ recv Notify → verify on-chain
  │ print txid + explorer link                  │   record_received(REAL sats)
  │ done                                        │   reconcile → advance ladder
```

In call order:

1. **Open the tunnel.** `tunnel::pay` (`tunnel.rs:351`) derives this agent's
   X25519 secret from the seed via `identity` (`tunnel.rs:358`, derivation branch
   3), parses the peer's WG public key (`tunnel.rs:359`), opens the signed ledger
   (`tunnel.rs:361`), reads the descriptors (`tunnel.rs:362`), binds a UDP socket
   (`tunnel.rs:364`), and runs the WireGuard initiator handshake with
   `FramedTunnel::connect` (`tunnel.rs:365`, handshake at `tunnel.rs:159`). A wrong
   peer key fails the handshake here, before any payment message is sent. On
   success it prints `[wg] tunnel established` (`tunnel.rs:366`) and calls
   `net::run_payer` (`tunnel.rs:367`).
2. **Amount gate.** `net::run_payer` (`net.rs:102`) loads policy (`net.rs:111`),
   folds the recent spend window with `led.spent_since` (`net.rs:112`), and runs
   `policy.check_amount` (`net.rs:113`) before the first message, so an over-limit
   payment never opens the conversation.
3. **Ask for an address.** Send `AddrRequest{sats}` (`net.rs:115`), then block
   until an `AddrResponse{address, index}` comes back (`net.rs:116-121`).
4. **Address gate.** `policy.check_address` (`net.rs:123`) checks the blocklist now
   that the destination is known.
5. **Build, record, broadcast.** `crate::pay::send` (`net.rs:126`, defined at
   `pay.rs:33`) is the ordering-critical core:
   - `chain::build_signed` (`pay.rs:41`, in `chain.rs:63`) fails closed on an
     uncapped mainnet policy (`chain.rs:74`), syncs the descriptor UTXOs from
     esplora (`chain.rs:78-81`), parses the recipient (`chain.rs:83`), picks the
     recommended feerate (`chain.rs:88`), lets bdk select coins and build
     (`chain.rs:89-92`), enforces the fee cap before signing (`chain.rs:96-101`),
     and Schnorr-signs (`chain.rs:103`), returning the signed tx *without*
     broadcasting.
   - `led.write_sidecar` (`pay.rs:48`) persists the raw signed tx as
     `pending/<txid>.tx`, fsync'd.
   - `led.append(Entry::Sent{… Status::Pending})` (`pay.rs:52`) writes the durable
     record *before* the money moves. This is the line that closes the
     crash-between-broadcast-and-record gap: after it, a crash cannot lose the
     payment.
   - `chain::broadcast` (`pay.rs:63`, in `chain.rs:447`) is the only step that
     moves money.
6. **Notify, then print.** Send `Notify{txid, sats}` over the tunnel
   (`net.rs:129`) as a fast-path hint, and print the txid and explorer link
   (`net.rs:130-132`). The Notify is not the source of truth; the receiver
   confirms on-chain.

### 2b. Offline path — `cli_sp_pay` → `pay::sp_send` → `chain::build_signed_to_sp`

```
   cm pay <sp-code> (payer A)                payee B (offline, no session)
 ══════════════════════════════            ═══════════════════════════════
 cli_sp_pay                                 (nothing needs to be running)
  │ check_amount + check_address(code)
  │ pay::sp_send:
  │   sp::decode(code) → (scan, spend, net)
  │   led.sp_utxos()  (spend earned SP income too)
  │   chain::build_signed_to_sp:
  │     sync + pin inputs,
  │     sp::send_address → one-time P2TR addr
  │     sign (bdk + manual key-path)          ┌── later, B runs cm serve / cm balance
  │   check_address(derived addr)             │   scan::scan_to_tip:
  │   write_sidecar → append Sent{Pending}    │     walk blocks, tx_matches →
  │   chain::broadcast → txid                 │     sp::receive_check (BIP-352)
  │   record_sp_spent(consumed inputs)        │   record_sp_received{Pending}
  │ print txid                                │   reconcile → confs → ladder → Final
  ▼ (no tunnel, no AddrRequest)               │   sp_utxos() now spendable
```

In call order:

1. **Spend gates.** `cli_sp_pay` (`main.rs:39`) opens the signed ledger
   (`main.rs:40`), loads policy (`main.rs:42`), and runs `check_amount`
   (`main.rs:44`) and `check_address` against the sp code handle (`main.rs:45`) —
   the offline path has no `net::run_payer` to gate it, so the check lives here.
   Then it calls `pay::sp_send` (`main.rs:47`).
2. **Decode and validate the code.** `pay::sp_send` (`pay.rs:78`) enforces the
   `SP_MIN_SATS` dust floor (`pay.rs:87`), decodes the code with `sp::decode`
   (`pay.rs:94`, in `sp.rs:77`) into `(scan, spend, network)`, and rejects a
   network mismatch before any money moves (`pay.rs:95-101`).
3. **Gather spendable inputs.** `led.sp_utxos()` (`pay.rs:105`, fold at
   `ledger.rs:438`) returns already-earned, fully-confirmed silent-payment outputs,
   and `wallet.sp_spend_keypair` (`pay.rs:106`) yields the key that redeems them.
   This is what makes SP income re-spendable: an agent pays an sp code with what it
   earned via silent payments, not only with descriptor UTXOs.
4. **Derive the one-time address and sign.** `chain::build_signed_to_sp`
   (`pay.rs:107`, in `chain.rs:121`) fails closed on uncapped mainnet
   (`chain.rs:131`), syncs (`chain.rs:135-137`), builds BIP-352 `SpInput`s from the
   SP UTXOs and descriptor UTXOs (`chain.rs:148-183`), computes the receiver's
   one-time Taproot address with `sp::send_address` (`chain.rs:184`, in `sp.rs:125`)
   over that exact input set, builds the tx with those inputs manually selected
   (`chain.rs:186-203`), enforces the fee cap (`chain.rs:205-210`), and signs:
   descriptor inputs by bdk, the SP inputs key-path Schnorr-signed by hand in
   `finalize_mixed_psbt` (`chain.rs:220-221`). It returns the tx, fee, derived
   address, and the SP outpoints it consumed.
5. **Belt-and-suspenders address gate.** Back in `pay::sp_send`, the derived
   one-time address is run through `check_address` (`pay.rs:109`). The sp code was
   already blocklist-checked; a one-time output cannot be pre-listed, so this
   catches the rare case where the derived address happens to match a blocked one.
6. **Record, broadcast, mark spent.** Same ordering as the live path:
   `write_sidecar` (`pay.rs:113`) → `append(Entry::Sent{… Pending})`
   (`pay.rs:114`) → `chain::broadcast` (`pay.rs:123`). Then, for each SP outpoint
   it just consumed, `led.record_sp_spent` (`pay.rs:125-127`, at `ledger.rs:368`)
   books an `SpSpent` so the balance fold stops counting it.

There is no tunnel, no `AddrRequest`/`AddrResponse`, and no `Notify`. The payee
learns it was paid only by scanning the chain (below).

## Receiver path

### 3a. Live path — `serve::run` → `net::run_receiver`

`serve::run` (`serve.rs:56`) is the resident seller. It takes the wallet's
exclusive lock (`serve.rs:65`), opens the signed ledger once (`serve.rs:68`), binds
one UDP socket (`serve.rs:69`), and loops (`serve.rs:92`) over three duties:
REPUBLISH the DHT card (`serve.rs:94`, `republish` at `serve.rs:144`, which
advertises the sp code at `serve.rs:145`), WATCH the chain (`serve.rs:100`), and
ACCEPT tunnels (`serve.rs:112`).

On ACCEPT, `FramedTunnel::accept_any` (`serve.rs:112`, at `tunnel.rs:252`) answers
a WireGuard handshake and *learns the initiator's key from the handshake itself*
(no CLI arg). It builds a `Receiver` (`serve.rs:115`) seeded with the next unused
index and runs `net::run_receiver` (`serve.rs:116`). Inside `net::run_receiver`
(`net.rs:27`), it loops on `wire.recv` (`net.rs:37`):

1. **`AddrRequest{sats}`** (`net.rs:39`): `rx.handle` (`net.rs:41`, at
   `protocol.rs:74`) derives the next unused BIP-86 address via
   `wallet.address(index)` (`protocol.rs:78`) and advances the index. The receiver
   appends `AddressIssued{index}` to the ledger (`net.rs:43`) and replies with
   `AddrResponse{address, index}` (`net.rs:47`). A fresh address per payment means
   no reuse.
2. **`Notify{txid, sats}`** (`net.rs:50`): treated as an *untrusted* hint. The
   receiver does not credit the claimed amount. It calls `chain::deposits_to` on
   the address it issued this session (`net.rs:62`, at `chain.rs:467`), finds the
   deposit whose txid matches (`net.rs:63`), and books the **real on-chain amount**
   with `led.record_received(&d.txid, d.sats, index)` (`net.rs:65`), then runs
   `ledger::reconcile` (`net.rs:66`). If the tx is not yet visible, it records
   nothing and lets the WATCH duty book it later. UDP has no close, so the function
   returns after one Notify (`net.rs:90`) rather than blocking the next buyer.

### 3b. Offline path — `serve` WATCH → `scan::scan_to_tip`

A silent payment lands on a one-time address the descriptors cannot know, so there
is nothing to poll for. The receiver must read the chain and run the BIP-352
receive check. The WATCH duty, `chain_watch` (`serve.rs:161`), does this every
tick:

1. **Advance in-flight payments.** `ledger::reconcile` (`serve.rs:162`) first
   (see the ladder below).
2. **Poll issued addresses.** For each address handed out but not yet paid
   (`led.issued_unpaid`), `chain::deposits_to` (`serve.rs:177`) plus
   `led.record_received` (`serve.rs:182`) book any plain-address deposit that
   arrived with no live session.
3. **Scan for silent payments.** `scan_fresh` (`serve.rs:203`, at `serve.rs:222`)
   opens a fresh ledger view and runs `scan::scan_to_tip` (`serve.rs:227`).

`scan::scan_to_tip` (`scan.rs:74`) takes the process scan lock (`scan.rs:77`),
loads the scan/spend keys (`scan.rs:79-80`), reads the tip height (`scan.rs:82`),
and starts from the saved checkpoint or `tip - START_LOOKBACK` (`scan.rs:83-87`).
It walks each block's transactions (`scan.rs:90-118`) and for every tx runs
`tx_matches` (`scan.rs:102`, at `scan.rs:168`), which reconstructs the tx's input
public keys with `input_pubkey` (`scan.rs:203`), extracts P2TR output keys with
`taproot_output_key` (`scan.rs:239`), and runs the BIP-352 receive check
`sp::receive_check` (`scan.rs:197`, at `sp.rs:146`). Each fresh match above the
dust floor (`scan.rs:103`) is booked as a Pending `SpReceived` via
`led.record_sp_received` (`scan.rs:107`, at `ledger.rs:342`), storing the ECDH
tweak so the spend key is recoverable from seed plus ledger alone. After a fully
successful pass it saves the checkpoint (`scan.rs:120`) and calls `track_spends`
(`scan.rs:121`, at `scan.rs:251`) to mark any of our SP outputs the chain now shows
spent.

### 3c. The status ladder — `ledger::reconcile`

Both receive shapes book a Pending entry and then advance it identically.
`ledger::reconcile` (`ledger.rs:650`) folds the work queue `led.pending()`
(`ledger.rs:505`) and, for each txid, asks the chain for its confirmation count
with `chain::confirmations` (`ledger.rs:653`, at `chain.rs:581`). It maps the count
to a status with `Status::from_confirmations` (`ledger.rs:675`, at `ledger.rs:48`):
0 confs = **Pending**, 1-2 = **Soft**, 3+ = **Final**. If the status changed it
appends a `StatusUpdate` (`ledger.rs:676-679`).

Two recovery behaviors ride along in reconcile:

- **Write-ahead rebroadcast.** A still-unconfirmed Sent that we hold a sidecar for
  is re-pushed with `chain::rebroadcast_hex` (`ledger.rs:663-665`). A provably-dead
  tx (inputs gone or conflicting) is marked `Failed` and un-debited
  (`ledger.rs:666-672`); anything else stays Pending. Once a payment reaches 1+
  confs its sidecar is removed (`ledger.rs:682-684`).
- **Orphan sidecars.** A sidecar with no matching Sent entry (a crash in the gap
  before the ledger append) is dropped, never rebroadcast blind
  (`ledger.rs:687-706`).

Once an `SpReceived` reaches Final, `led.sp_utxos` (`ledger.rs:438`) returns it as
spendable, which feeds directly back into `pay::sp_send`'s input gathering. That is
the loop that makes earned silent-payment income re-spendable.

## Offline vs live, side by side

| Step | Live (tunnel) path | Offline (sp-code) path |
|---|---|---|
| Peer resolution | `pubkey@host:port`, or a card with endpoints | `sp1…`/`tsp1…`, or a card carrying an sp code |
| WireGuard tunnel | **yes** (`tunnel::pay` → `FramedTunnel::connect`) | **skipped** |
| Address agreement | `AddrRequest`/`AddrResponse` over the tunnel (fresh BIP-86 address) | `sp::send_address` derives a one-time output offline (BIP-352) |
| Payee must be online | yes | no |
| Build/record/broadcast | `pay::send` → `chain::build_signed` | `pay::sp_send` → `chain::build_signed_to_sp` |
| `Notify` hint | sent over the tunnel | none |
| Receiver detection | `net::run_receiver` (Notify + on-chain verify) or WATCH poll | `scan::scan_to_tip` (chain scan) |
| Confirmation ladder | `ledger::reconcile` (identical) | `ledger::reconcile` (identical) |

The offline path skips exactly the WireGuard tunnel and the interactive
address request. Everything to the right of "agree on the destination address" is
the same build → record → broadcast → reconcile machinery.

## Framing detail (live path)

Each `Message` is `serde_json`-encoded as a length-prefixed frame
(`Message::encode`, `protocol.rs:33`), wrapped in a minimal IPv4 packet
(`wrap_ip`, `tunnel.rs:128` — WireGuard tunnels IP, so each frame rides inside
one), encrypted by WireGuard's ChaCha20-Poly1305 (`WgCore::seal` →
`encapsulate`, `tunnel.rs:114`), and sent as a UDP datagram. Inbound,
`WgCore::process` (`tunnel.rs:102`) decapsulates and `Message::decode`
(`protocol.rs:45`) reassembles. The plaintext JSON never appears in the encrypted
datagram, verified by a test in `tunnel.rs`.

## The split, in one line

**WireGuard moves messages; Bitcoin L1 moves money; `cm` is the bridge.** The
tunnel carries `AddrRequest` / `AddrResponse` / `Notify` and nothing of value; the
coins move over the Bitcoin network and are confirmed by the chain. The payment
logic in `net.rs` does not know which transport carries its bytes: swap the tunnel
for the TCP stand-in in the tests and the logic above does not move. The offline
silent-payment path removes the transport entirely and lets the chain itself be the
channel.
