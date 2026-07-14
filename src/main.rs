//! computermoney — milestone 1 CLI.
//!
//! Build ladder step 1: turn a mnemonic into a signet Taproot address.
//! No tunnel, no chain sync yet — just the wallet root the rest builds on.

mod chain;
mod discover;
mod ledger;
mod mcp;
mod net;
mod pay;
mod policy;
mod protocol;
mod storage;
mod tunnel;
mod wallet;

use wallet::Wallet;
use zeroize::Zeroizing;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn ledger_status_label(confs: u32) -> &'static str {
    match ledger::Status::from_confirmations(confs) {
        ledger::Status::Pending => "pending",
        ledger::Status::Soft => "soft",
        ledger::Status::Final => "final",
        ledger::Status::Failed => "failed",
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("init") => {
            // Each init creates a NEW identity in its own directory —
            // running it again never overwrites an existing wallet.
            let (w, phrase) = Wallet::generate()?;
            let phrase = Zeroizing::new(phrase); // wipe the new mnemonic on drop
            let id = w.id_hex()?;
            println!("identity: {id}");
            println!("address[0]: {}", w.address(0)?);
            let pass = std::env::var("CM_PASSPHRASE").ok();
            if pass.is_none() && storage::network_label() == "mainnet" {
                println!("mnemonic: {}", phrase.as_str());
                eprintln!("\nset CM_PASSPHRASE before init to seal the seed to disk.");
                eprintln!("until then this mnemonic is the whole wallet — back it up.");
            } else {
                let dir = storage::save_new_wallet(&w, phrase.as_str(), pass.as_deref())?;
                if pass.is_some() {
                    println!("seed encrypted -> {}", dir.join("seed.enc").display());
                    eprintln!("\nseed is sealed with CM_PASSPHRASE. lose the passphrase, lose the wallet.");
                } else {
                    println!("mnemonic: {}", phrase.as_str());
                    println!("mnemonic saved (plaintext) -> {}", dir.join("mnemonic").display());
                    eprintln!("\n{} wallet stored unencrypted — fine for test coins.", storage::network_label());
                    eprintln!("set CM_PASSPHRASE before init to seal it instead.");
                }
                if storage::wallet_ids().len() > 1 {
                    eprintln!("\nseveral identities live here now — use this one with:");
                    eprintln!("  export CM_ID={}", &id[..8]);
                }
            }
        }
        Some("setup") => {
            // Zero-to-ready in one command: create a wallet if none exists,
            // then print identity, funding address, balance, and how to
            // transact. With CM_PASSPHRASE the seed is sealed to disk; on a
            // test network without one, the mnemonic is stored plaintext
            // (mainnet insists on the passphrase). More identities: cm init.
            let label = storage::network_label();
            if storage::wallet_ids().is_empty() {
                let pass = std::env::var("CM_PASSPHRASE").ok();
                if pass.is_none() && label == "mainnet" {
                    return Err("cm setup seals your wallet with a passphrase: \
                                export CM_PASSPHRASE='…' then run `cm setup` again"
                        .into());
                }
                let (w, phrase) = Wallet::generate()?;
                let phrase = Zeroizing::new(phrase);
                let dir = storage::save_new_wallet(&w, phrase.as_str(), pass.as_deref())?;
                if pass.is_some() {
                    println!("✓ wallet created and sealed -> {}", dir.join("seed.enc").display());
                    println!();
                    println!("BACK UP these 12 words — the only recovery if you lose the passphrase:");
                } else {
                    println!("✓ wallet created -> {} (plaintext mnemonic, {label} test coins)", dir.join("mnemonic").display());
                    println!();
                    println!("BACK UP these 12 words:");
                }
                println!("  {}", phrase.as_str());
                println!();
            }
            let w = storage::load_wallet()?;
            println!("network:  {label}");
            println!("identity: {}", w.id_hex()?);
            println!("address:  {}", w.address(0)?);
            let (ext, int) = w.descriptors();
            match chain::balance(&ext, &int) {
                Ok(b) => println!("balance:  {} sats confirmed ({} pending)", b.confirmed, b.pending),
                Err(_) => println!("balance:  (chain unreachable right now — retry `cm setup`)"),
            }
            println!();
            println!("receive a payment:  cm receive <payer-pubkey>");
            println!("pay a peer:         cm pay <peer-pubkey>@<host:port> <sats>");
            if label == "mainnet" {
                println!("\nfund the address above by sending BTC to it, then run `cm setup` again.");
            } else {
                println!("\nfund the address above (signet faucet: https://faucet.mutinynet.com/).");
            }
        }
        Some("address") => {
            let w = storage::load_wallet()?;
            let idx: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            println!("{}", w.address(idx)?);
        }
        Some("balance") => {
            let w = storage::load_wallet()?;
            let (ext, int) = w.descriptors();
            eprintln!("syncing from {}…", storage::network_label());
            let b = chain::balance(&ext, &int)?;
            println!("network:   {}", storage::network_label());
            println!("confirmed: {} sats", b.confirmed);
            println!("pending:   {} sats", b.pending);
        }
        Some("id") => {
            let w = storage::load_wallet()?;
            let card = discover::card_pubkey_hex(&*w.card_secret_bytes()?);
            println!("{card}");
            eprintln!("(your card key — the one thing you share. publish where to reach you with");
            eprintln!(" `cm publish <your-host:port>`; a peer then pays you with `cm pay {card} <sats>`.)");
        }
        Some("publish") => {
            // Sign and put our business card to the DHT: the WG endpoint a
            // payer tunnels to, addressed by our ed25519 card key. Opt-in —
            // publishing ties this endpoint to the card identity, so it runs
            // only when the agent deliberately wants to be reachable.
            let usage = "usage: publish <your-host:port>";
            let endpoint = args.get(2).ok_or(usage)?;
            let w = storage::load_wallet()?;
            let card = discover::Card {
                wg: format!("{}@{}", w.id_hex()?, endpoint),
                at: ledger::now_unix(),
            };
            eprintln!("publishing card to the DHT…");
            discover::publish(&*w.card_secret_bytes()?, &card)?;
            println!("published: {}", card.wg);
            eprintln!("(peers reach you by your card key: cm id)");
        }
        Some("resolve") => {
            let usage = "usage: resolve <card-key>";
            let key = discover::parse_card_key(args.get(2).ok_or(usage)?)?;
            eprintln!("resolving from the DHT…");
            match discover::resolve(&key)? {
                Some(card) => {
                    println!("wg: {}", card.wg);
                    println!("at: {}", card.at);
                }
                None => println!("(no card found for that key)"),
            }
        }
        Some("receive") => {
            let usage = "usage: receive <payer-pubkey-hex> [bind-udp-addr]";
            let peer = args.get(2).ok_or(usage)?;
            let bind = args.get(3).map(String::as_str).unwrap_or("0.0.0.0:51820");
            let w = storage::load_wallet()?;
            tunnel::serve(&w, &storage::ledger_path(&w)?, bind, peer)?;
        }
        Some("pay") => {
            // Two forms. `pay <pubkey>@<host:port> <sats>` is the manual path
            // (you already know the endpoint). `pay <card-key> <sats>` is the
            // DHT path: resolve the peer's card to their current WG endpoint,
            // then the same tunnel + Bitcoin settle. Discovery is the only new
            // step — everything after the `@` split is identical.
            let usage = "usage: pay <card-key | pubkey@host:port> <sats>";
            let peer = args.get(2).ok_or(usage)?;
            let sats: u64 = args.get(3).ok_or(usage)?.parse()?;
            let w = storage::load_wallet()?;
            let (peer_pub, peer_addr) = match peer.split_once('@') {
                Some((pubkey, addr)) => (pubkey.to_string(), addr.to_string()),
                None => {
                    let key = discover::parse_card_key(peer)?;
                    eprintln!("resolving card {}… (DHT)", &peer[..8]);
                    let card = discover::resolve(&key)?
                        .ok_or("no card found on the DHT for that key")?;
                    let (pubkey, addr) = card
                        .wg
                        .split_once('@')
                        .ok_or("resolved card has a malformed wg endpoint")?;
                    eprintln!("found endpoint: {}", card.wg);
                    (pubkey.to_string(), addr.to_string())
                }
            };
            tunnel::pay(&w, &storage::ledger_path(&w)?, &peer_addr, &peer_pub, sats)?;
        }
        Some("mcp") => {
            // Run the stdio MCP server: an AI agent drives cm_send / cm_balance
            // over JSON-RPC. The wallet unlocks once and serves until stdin closes.
            mcp::run()?;
        }
        Some("confs") => {
            let txid = args.get(2).ok_or("usage: confs <txid>")?;
            let n = chain::confirmations(txid)?;
            println!("{n} confirmations ({})", ledger_status_label(n));
        }
        Some("send") => {
            let to = args.get(2).ok_or("usage: send <address> <sats>")?;
            let sats: u64 = args.get(3).ok_or("usage: send <address> <sats>")?.parse()?;
            let w = storage::load_wallet()?;
            let mut led = ledger::Ledger::open_with_identity(&storage::ledger_path(&w)?, w.signing_keypair()?)?;
            let policy = policy::Policy::load()?;
            let spent = led.spent_since(ledger::now_unix().saturating_sub(policy::DAILY_WINDOW_SECS));
            policy.check_amount(sats, spent)?;
            policy.check_address(to)?;
            let (ext, int) = w.descriptors();
            eprintln!("syncing + building + broadcasting…");
            let txid = pay::send(&mut led, &ext, &int, to, sats, policy.max_fee_sats)?;
            println!("txid: {txid}");
        }
        Some("policy") => {
            let p = policy::Policy::load()?;
            let path = storage::config_path("CM_POLICY", "policy.json");
            println!("max_payment_sats:  {:?}", p.max_payment_sats);
            println!("daily_limit_sats:  {:?}", p.daily_limit_sats);
            println!("max_fee_sats:      {:?}", p.max_fee_sats);
            println!("blocked_addresses: {}", p.blocked_addresses.len());
            eprintln!("\npolicy file: {} ({})", path.display(),
                if path.exists() { "loaded" } else { "absent — no limits" });
        }
        _ => {
            eprintln!("usage:");
            eprintln!("  cm setup                         create+seal a wallet, show how to fund and transact");
            eprintln!("  cm init                          create a wallet (seals seed if CM_PASSPHRASE)");
            eprintln!("  cm id                            print your card key (the one thing you share)");
            eprintln!("  cm publish <your-host:port>      announce your WireGuard endpoint on the DHT");
            eprintln!("  cm resolve <card-key>            look up a peer's endpoint on the DHT");
            eprintln!("  cm receive <payer-pubkey> [bind] wait for a payment over WireGuard");
            eprintln!("  cm pay <card-key> <sats>         discover (DHT) -> talk (WireGuard) -> settle (Bitcoin)");
            eprintln!("  cm pay <pubkey@host:port> <sats> pay a known endpoint directly (no DHT)");
            eprintln!();
            eprintln!("  cm balance                       on-chain balance");
            eprintln!("  cm address [n]                   a receive address (to fund the wallet)");
            eprintln!("  cm send <addr> <sats>            raw on-chain send to an address");
            eprintln!("  cm confs <txid>                  confirmation count for a txid");
            eprintln!("  cm policy                        show the spend policy (limits/fee/blocklist)");
            eprintln!("  cm mcp                           stdio MCP server (cm_send, cm_balance) for AI agents");
            eprintln!();
            eprintln!("identities: each `cm init` is one agent, stored under ~/.config/computermoney/<id8>/;");
            eprintln!("            several on one machine? pick with CM_ID=<identity prefix>.");
            eprintln!("wallet unlock: encrypted seed (CM_PASSPHRASE) or the stored mnemonic; CM_MNEMONIC overrides.");
            eprintln!("network: CM_NETWORK = mainnet (default) | testnet | signet.");
            std::process::exit(2);
        }
    }
    Ok(())
}
