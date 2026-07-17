# Demo video: showing DHT → WireGuard → Bitcoin L1

A ~2-minute screen recording where an agent pays another agent in Bitcoin, and you can
*see* each of the three layers move. The buyer is driven in plain language through MCP; the
seller is a background daemon. Everything is **signet** (worthless coins, 30-second blocks).

## Recording setup

Lay out four panes:

- **Claude** (the MCP client) — where you type the buyer's instruction. Large, left half.
- **Seller daemon** terminal (top-right): the `cm serve` log.
- **tcpdump** terminal (mid-right): proves the tunnel is encrypted.
- **Browser** (bottom-right / full-screen for the L1 beat): the block explorer.

Prep before you hit record (off camera):

```sh
export CM_NETWORK=signet
CM_HOME=~/cm-seller cm setup            # seller wallet (needs no coins)
CM_HOME=~/cm-seller cm id               # -> SELLER CARD KEY, keep it on a sticky note
```

Confirm the buyer (your registered MCP wallet) has signet funds: ask Claude *"what's my
computermoney balance?"* — it should show a few thousand sats. If not, fund the address from
<https://faucet.mutinynet.com/>. Make sure Claude shows the `cm_pay` tool (restart it if you
only see `cm_send`/`cm_balance`).

---

## Scene 1 — the cast (0:00–0:20)

**On screen:** the seller terminal. Start the daemon.

```sh
CM_HOME=~/cm-seller cm serve --bind 127.0.0.1:51820 --ep 127.0.0.1:51820
```

**Say:** "Two AI agents, one machine, each with its own Bitcoin wallet. This is the seller.
It has no address book and no server — its only public handle is a *card key*."

## Scene 2 — DHT: the card goes up (0:20–0:40)

**On screen:** highlight the seller line `[serve] published card <wg-key> @ 127.0.0.1:51820`,
and keep the **card key** from `cm id` (Scene setup) visible on its sticky note.

**Say:** "The seller signs a tiny card — its tunnel endpoint — and publishes it to the public
BitTorrent DHT. No server hosts it. Any agent that knows the key can look the seller up,
anywhere in the world." *(Callout: the payable lookup key is the `cm id` value; the log line
above just confirms the publish is live. The hex in the log is the tunnel key inside the
card, not the lookup key — don't paste that one.)*

## Scene 3 — WireGuard: the tunnel (0:40–1:10)

**On screen:** Claude. Type the buyer's instruction:

> **pay 5000 sats to `<seller-card-key>`**

As `cm_pay` runs, the buyer shows `resolving card …(DHT)` → `dialing … @ 127.0.0.1:51820`,
and the seller flips to `[serve] session opened with <buyer-key>`.

Cut to the tcpdump pane (start it just before you send):

```sh
sudo tcpdump -i lo0 -X udp port 51820
```

**Say:** "One sentence. The buyer resolves that card on the DHT, then opens a *real*
WireGuard tunnel — keyed by the wallet seed, not a password. Watch the wire: it's pure
ciphertext. The amount, the address, everything the two agents say is encrypted." *(Callout:
the hex dump — no readable JSON.)*

## Scene 4 — Bitcoin L1: settle (1:10–1:45)

**On screen:** `cm_pay` returns `txid …` and an explorer URL. Open it.

**Say:** "The buyer builds one Bitcoin transaction, signs it with its key, and broadcasts it.
Here it is on the chain — 5000 sats to the address the seller just handed out." *(Show the tx
on mutinynet.)*

Back to the seller log: `verified <txid> pays 5000 sat to our address`. Then in Claude:

> **did a payment arrive? show collections** → `cm_collections` (shows *paid*)
> **confirmations on `<txid>`?** → `cm_confs` (→ *final*)

**Say:** "The seller doesn't trust the buyer's word — it reads the *chain*, confirms the tx
really pays its address, and books the real amount. Three confirmations: final."

## Scene 5 — the point (1:45–2:00)

**Say:** "No custodian ever held the coins. No account, no server. One seed is the identity
for both the money and the channel — the key *is* the agent. That's computermoney."

**On screen:** the repo + `curl -fsSL …/install.sh | sh`.

---

## 60-second cut

Drop Scene 1 and the explorer beat. Sequence: card key on screen (5s) → *"pay 5000 sats to
this"* in Claude (10s) → DHT-resolve + tunnel logs + tcpdump ciphertext (20s) → txid returned
+ seller `verified … pays 5000` + `cm_confs` final (20s) → one-line close (5s).

## Layer cheat-sheet (keep visible while editing)

| Beat | The one thing to show |
|---|---|
| DHT | seller `published card <key>` — no server holds it |
| WireGuard | tcpdump ciphertext + `session opened with <key>` |
| Bitcoin L1 | the txid on the explorer + `verified … pays 5000 sat` |
