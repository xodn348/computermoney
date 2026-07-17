# Two agents on testnet, in two terminals

Run the whole pipeline — **discover (DHT) → talk (WireGuard) → settle (Bitcoin L1)** —
between a seller and a buyer on one machine. Each is a separate identity with its own
wallet store (`CM_HOME`), so they never share a ledger. Everything is testnet, so no real
BTC moves.

Two keys, do not mix them up:

- **card key** — printed by `cm id` (ed25519, the DHT lookup key). The buyer pays to *this*:
  `cm pay <card-key> <sats>`.
- **WG pubkey** — printed by `cm setup` as `identity:` (X25519, the tunnel key). Only used
  for the DHT-less direct path `cm pay <wg-pubkey>@host:port <sats>`.

For the real DHT→WG→L1 test, use the **card key** path.

---

## Terminal 1 — seller (agent B)

The seller receives, so it needs no coins. It just runs the daemon.

```sh
export CM_NETWORK=testnet
export CM_HOME=~/cm-seller

cm setup            # creates B's wallet; note the `identity:` line (B's WG pubkey)
cm id               # prints B's CARD KEY — copy this, the buyer needs it

cm serve --bind 127.0.0.1:51820 --ep 127.0.0.1:51820
#   publishes B's card to the DHT (keyed by the card key, endpoint 127.0.0.1:51820),
#   then waits: republishes every 45 min, watches the chain every 60 s, and accepts
#   any buyer's WireGuard handshake. Leave this running.
```

`--ep 127.0.0.1:51820` is correct only because the buyer is on the *same machine*. For two
different machines, use the seller's reachable address (`--ep <public-ip>:51820`) and open
UDP 51820.

## Terminal 2 — buyer (agent A)

The buyer spends, so it must be funded first.

```sh
export CM_NETWORK=testnet
export CM_HOME=~/cm-buyer

cm setup            # creates A's wallet; FUND the `address:` line from a testnet faucet
```

Fund that address from a testnet3 faucet, for example:
<https://bitcoinfaucet.uo1.net/> or <https://coinfaucet.eu/en/btc-testnet/>. Then wait for
one confirmation and check it arrived:

```sh
cm balance          # confirmed should be > 0 before you try to pay
```

Now pay the seller by its **card key** (the `cm id` output from terminal 1):

```sh
cm pay <B-card-key> 5000
#   resolve B's card on the DHT -> open the WireGuard tunnel to 127.0.0.1:51820 ->
#   ask for a fresh address -> broadcast 5000 testnet sats -> notify B.
```

## What you should see

- **Terminal 2 (buyer):** `resolving card …`, `dialing … @ 127.0.0.1:51820`, then
  `[pay] address (index N): tb1p…`, `[pay] txid …`, and a `cm confs <txid>` follow-up line.
- **Terminal 1 (seller):** `[serve] session opened with <buyer-wg-key>`,
  `[recv] issued index N …`, then
  `[recv] verified <txid> pays 5000 sat to our address …`. Within ~60 s the chain-watch
  logs the deposit and, once it confirms, advances it to final.

Check balances any time:

```sh
CM_HOME=~/cm-seller cm balance    # 5000 sats, pending then confirmed
CM_HOME=~/cm-buyer   cm balance    # dropped by 5000 + fee
```

---

## Notes and troubleshooting

- **Testnet3 is slow and its faucets are often dry.** Blocks are ~10 min, so 3-confirmation
  *final* can take 30+ min. If the faucet is empty or you want a fast loop, switch both
  terminals to **signet** instead — 30-second blocks (3-conf final ≈ 90 s) and a reliable
  faucet. One change: `export CM_NETWORK=signet`, then fund from
  <https://faucet.mutinynet.com/>. Everything else is identical. Signet is the smoother
  experiment; testnet is fine if you specifically want testnet3.

- **`no card found on the DHT for that key`** — the card has not propagated yet. Give it
  30–60 s after `cm serve` starts and re-run `cm pay`. To isolate the WireGuard + Bitcoin
  legs from the DHT entirely, use the direct path with B's **WG pubkey** (the `identity:`
  line from B's `cm setup`):

  ```sh
  cm pay <B-wg-pubkey>@127.0.0.1:51820 5000
  ```

- **Notify is verified, not trusted.** The seller books the amount the *chain* reports for
  the deposit to the address it issued — never the amount the buyer claims. A lying or
  inflated `Notify` credits nothing; the periodic chain-watch is the backstop that books
  real deposits even if the tunnel drops.

- **Reset an identity:** `rm -rf ~/cm-seller ~/cm-buyer` and start over (testnet coins are
  worthless, so this is safe).
