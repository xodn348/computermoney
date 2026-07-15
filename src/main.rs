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
mod serve;
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

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("setup") => {
            // Zero-to-ready in one command: create a wallet if none exists,
            // then print identity, funding address, balance, and how to
            // transact. With CM_PASSPHRASE the seed is sealed to disk; on a
            // test network without one, the mnemonic is stored plaintext
            // (mainnet insists on the passphrase).
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
            println!("share your card key:  cm id");
            println!("be reachable:         cm publish <your-host:port>");
            println!("pay a peer:           cm pay <card-key> <sats>");
            if label == "mainnet" {
                println!("\nfund the address above by sending BTC to it, then run `cm setup` again.");
            } else {
                println!("\nfund the address above (signet faucet: https://faucet.mutinynet.com/).");
            }
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
            let card = discover::card_pubkey_hex(&*w.wg_secret_bytes()?);
            println!("{card}");
            eprintln!("(your card key — the one thing you share. publish where to reach you with");
            eprintln!(" `cm publish <your-host:port>`; a peer then pays you with `cm pay {card} <sats>`.)");
        }
        Some("publish") => {
            // Sign and put our business card to the DHT: the WG endpoint a
            // payer tunnels to, addressed by our ed25519 card key. Opt-in —
            // publishing ties this endpoint to the card identity, so it runs
            // only when the agent deliberately wants to be reachable.
            // Zero or more endpoints (usage: publish [host:port ...]): a
            // dial-out-only buyer publishes none (just its WG identity), a
            // dual-stack peer publishes several.
            let ep: Vec<String> = args[2..].to_vec();
            let w = storage::load_wallet()?;
            let card = discover::Card {
                wg: w.id_hex()?,
                ep,
                at: ledger::now_unix(),
            };
            eprintln!("publishing card to the DHT…");
            discover::publish(&*w.wg_secret_bytes()?, &card)?;
            if card.ep.is_empty() {
                println!("published: {} (no endpoint — dial-out only)", card.wg);
            } else {
                println!("published: {} @ {}", card.wg, card.ep.join(", "));
            }
            eprintln!("(peers reach you by your card key: cm id)");
        }
        Some("serve") => {
            // The resident seller: one daemon that republishes its card,
            // watches the chain, and accepts any buyer's tunnel. `--bind` sets
            // the UDP listen address; `--ep` is repeatable and lists the
            // endpoints the card advertises (none = card key still resolves,
            // dial-out only).
            let mut bind = "0.0.0.0:51820".to_string();
            let mut eps: Vec<String> = Vec::new();
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--bind" => {
                        bind = args.get(i + 1).ok_or("--bind needs an address")?.clone();
                        i += 2;
                    }
                    "--ep" => {
                        eps.push(args.get(i + 1).ok_or("--ep needs a host:port")?.clone());
                        i += 2;
                    }
                    other => return Err(format!("unknown serve argument: {other}").into()),
                }
            }
            let w = storage::load_wallet()?;
            serve::run(&w, &storage::ledger_path(&w)?, &bind, eps)?;
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
            match peer.split_once('@') {
                Some((peer_pub, peer_addr)) => {
                    tunnel::pay(&w, &storage::ledger_path(&w)?, peer_addr, peer_pub, sats)?;
                }
                None => {
                    let key = discover::parse_card_key(peer)?;
                    eprintln!("resolving card {}… (DHT)", &peer[..8]);
                    let card = discover::resolve(&key)?
                        .ok_or("no card found on the DHT for that key")?;
                    if card.ep.is_empty() {
                        return Err(
                            "peer published no endpoint (not accepting inbound sessions)".into(),
                        );
                    }
                    // Try each published endpoint (v4, v6, …) in order until
                    // one session succeeds; if all fail, surface the last error.
                    let ledger = storage::ledger_path(&w)?;
                    let mut last_err = None;
                    for addr in &card.ep {
                        eprintln!("dialing {} @ {addr}…", card.wg);
                        match tunnel::pay(&w, &ledger, addr, &card.wg, sats) {
                            Ok(()) => {
                                last_err = None;
                                break;
                            }
                            Err(e) => last_err = Some(e),
                        }
                    }
                    if let Some(e) = last_err {
                        return Err(e);
                    }
                }
            }
        }
        Some("mcp") => {
            // Run the stdio MCP server: an AI agent drives cm_send / cm_balance
            // over JSON-RPC. The wallet unlocks once and serves until stdin closes.
            mcp::run()?;
        }
        _ => {
            eprintln!("the pipeline: discover (DHT) -> talk (WireGuard) -> settle (Bitcoin L1)");
            eprintln!();
            eprintln!("  cm setup                         create a wallet, show how to fund and transact");
            eprintln!("  cm id                            print your card key (the one thing you share)");
            eprintln!("  cm publish <your-host:port>      announce your WireGuard endpoint on the DHT");
            eprintln!("  cm serve [--bind a] [--ep h:p]…  resident seller: republish, watch chain, accept payments");
            eprintln!("  cm pay <card-key> <sats>         discover -> talk -> settle, in one command");
            eprintln!("  cm pay <pubkey@host:port> <sats> pay a known endpoint directly (no DHT)");
            eprintln!("  cm balance                       on-chain balance");
            eprintln!("  cm mcp                           stdio MCP server (cm_send, cm_balance) for AI agents");
            eprintln!();
            eprintln!("wallet unlock: encrypted seed (CM_PASSPHRASE) or the stored mnemonic; CM_MNEMONIC overrides.");
            eprintln!("network: CM_NETWORK = mainnet (default) | testnet | signet.");
            std::process::exit(2);
        }
    }
    Ok(())
}
