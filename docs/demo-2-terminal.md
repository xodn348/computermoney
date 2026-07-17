# Two-terminal demo: same pipeline, CLI or MCP

One machine, two terminals, the full **discover (DHT) → talk (WireGuard) → settle
(Bitcoin L1)** pipeline between two agents. Everything is **signet** (worthless coins,
30-second blocks, 3-conf *final* ≈ 90 s).

The seller is always a daemon in **terminal 1** — identical for both tracks. Only
**terminal 2**, the buyer, differs:

- **Track A — CLI:** the buyer types `cm pay`.
- **Track B — MCP:** the buyer's agent calls `cm_pay` from a plain sentence.

The seller can't be "started" over MCP (a daemon does not fit MCP's request/response model),
so its one line is CLI in both tracks. Everything a person *asks* still goes through MCP in
Track B.

---

## Shared setup (once, off camera)

Two keys, do not confuse them:
- **card key** = `cm id` output (ed25519). The buyer pays to *this*.
- **WG pubkey** = `cm setup` `identity:` line (x25519). Only for the DHT-less direct path.

```sh
export CM_NETWORK=signet

# Seller identity (needs no coins). Copy its CARD KEY.
CM_HOME=~/cm-seller cm setup
CM_HOME=~/cm-seller cm id            # -> <SELLER-CARD-KEY>

# Buyer must have signet funds. The MCP demo wallet (default store) already does;
# check it, and top up from https://faucet.mutinynet.com/ if needed.
cm balance
```

---

## Terminal 1 — seller (both tracks)

```sh
export CM_NETWORK=signet
CM_HOME=~/cm-seller cm serve --bind 127.0.0.1:51820 --ep 127.0.0.1:51820
```

Leave it running. It publishes the card to the DHT, accepts any buyer's WireGuard handshake,
and books deposits from the chain. Its log is your seller-side view.

## Terminal 2 — buyer

### Track A — CLI

```sh
export CM_NETWORK=signet
cm pay <SELLER-CARD-KEY> 5000        # discover -> talk -> settle
cm confs <txid>                      # from the pay output; watch it reach final
cm balance                           # dropped by 5000 + fee
```

### Track B — MCP

Terminal 2 runs your MCP client — **Claude Code in a terminal** (`claude`), or Claude
Desktop. First-time only: the registered `computermoney` server must expose `cm_pay`; if you
only see `cm_send`/`cm_balance`, **restart the client** so it relaunches on the current
binary. Then, in plain language:

> **pay 5000 sats to `<SELLER-CARD-KEY>`** → `cm_pay` → returns txid + explorer URL
> **confirmations on `<txid>`?** → `cm_confs` → pending → soft → final
> **what's my balance?** → `cm_balance`

To watch the *seller* side over MCP too, register the seller as its own server (optional):

```sh
claude mcp add -s user computermoney-seller \
  -e CM_NETWORK=signet -e CM_HOME="$HOME/cm-seller" -- "$HOME/.cargo/bin/cm" mcp
```

Then ask it: **show collections** → `cm_collections` (the issued address flips to *paid*).

Both tracks hit the exact same ledger-first settle path; the only difference is who types the
verb.

---

## Watching each layer move (both tracks)

Keep the seller log (terminal 1) visible and add a sniffer.

| Layer | What proves it | Where |
|---|---|---|
| **DHT** | seller `[serve] published card …`; buyer `resolving card <8hex>… (DHT)` then `dialing …`. The card is a signed BEP-44 record on the public BitTorrent DHT — no server holds it. | daemon log + buyer output |
| **WireGuard** | buyer `[wg] tunnel established`; seller `[serve] session opened with <buyer-key>`. And the wire is real ciphertext: `sudo tcpdump -i lo0 -X udp port 51820` shows encrypted bytes, never the JSON. | logs + `tcpdump` |
| **Bitcoin L1** | the returned `txid` on `https://mutinynet.com/tx/<txid>`; seller `[recv] verified <txid> pays 5000 sat to our address`; `cm confs` / `cm_confs` → *final*. | explorer + logs |

The seller's `verified … pays 5000 sat` line is the point: the receipt comes from the chain,
matched to the address it issued — never from the buyer's claim.

---

## Notes

- **`cm_pay` missing in the MCP client?** Restart it (see Track B).
- **`no card found on the DHT`** — give the daemon 30–60 s to propagate, then retry. To skip
  the DHT and test only WireGuard + L1: `cm pay <SELLER-WG-PUBKEY>@127.0.0.1:51820 5000`
  (WG pubkey = the seller's `cm setup` `identity:` line). No MCP form for this.
- **Two machines instead of two terminals:** give the seller a reachable endpoint
  (`--ep <public-ip>:51820`, open UDP 51820); the buyer resolves the same card key. The rest
  is unchanged.
- **Reset:** `rm -rf ~/cm-seller` (signet coins are worthless).
- **Testnet3** works the same with `CM_NETWORK=testnet`, but blocks are ~10 min and faucets
  are often dry; signet is the smoother demo.
