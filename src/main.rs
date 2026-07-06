//! computermoney — milestone 1 CLI.
//!
//! Build ladder step 1: turn a mnemonic into a signet Taproot address.
//! No tunnel, no chain sync yet — just the wallet root the rest builds on.

mod chain;
mod demo;
mod ledger;
mod mcp;
mod net;
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
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("init") => {
            let (w, phrase) = Wallet::generate()?;
            let phrase = Zeroizing::new(phrase); // wipe the new mnemonic on drop
            println!("address[0]: {}", w.address(0)?);
            if let Ok(pass) = std::env::var("CM_PASSPHRASE") {
                let path = storage::seed_path();
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                storage::save_encrypted(phrase.as_str(), &pass, &path)?;
                println!("seed encrypted -> {}", path.display());
                eprintln!("\nseed is sealed with CM_PASSPHRASE. lose the passphrase, lose the wallet.");
            } else if storage::network_label() != "mainnet" {
                let path = storage::save_plaintext_mnemonic(phrase.as_str())?;
                println!("mnemonic: {}", phrase.as_str());
                println!("mnemonic saved (plaintext) -> {}", path.display());
                eprintln!("\n{} wallet stored unencrypted — fine for test coins.", storage::network_label());
                eprintln!("set CM_PASSPHRASE before init to seal it instead.");
            } else {
                println!("mnemonic: {}", phrase.as_str());
                eprintln!("\nset CM_PASSPHRASE before init to seal the seed to disk.");
                eprintln!("until then this mnemonic is the whole wallet — back it up.");
            }
        }
        Some("setup") => {
            // Zero-to-ready in one command: create a wallet (idempotent),
            // then print identity, funding address, balance, and how to
            // transact. With CM_PASSPHRASE the seed is sealed to disk; on a
            // test network without one, the mnemonic is stored plaintext
            // (mainnet insists on the passphrase).
            let label = storage::network_label();
            let seed_path = storage::seed_path();
            if !seed_path.exists() && !storage::mnemonic_path().exists() {
                let pass = std::env::var("CM_PASSPHRASE");
                if pass.is_err() && label == "mainnet" {
                    return Err("cm setup seals your wallet with a passphrase: \
                                export CM_PASSPHRASE='…' then run `cm setup` again"
                        .into());
                }
                let (_w, phrase) = Wallet::generate()?;
                let phrase = Zeroizing::new(phrase);
                if let Ok(pass) = pass {
                    if let Some(dir) = seed_path.parent() {
                        std::fs::create_dir_all(dir)?;
                    }
                    storage::save_encrypted(phrase.as_str(), &pass, &seed_path)?;
                    println!("✓ wallet created and sealed -> {}", seed_path.display());
                    println!();
                    println!("BACK UP these 12 words — the only recovery if you lose the passphrase:");
                    println!("  {}", phrase.as_str());
                    println!();
                } else {
                    let path = storage::save_plaintext_mnemonic(phrase.as_str())?;
                    println!("✓ wallet created -> {} (plaintext mnemonic, {label} test coins)", path.display());
                    println!();
                    println!("BACK UP these 12 words:");
                    println!("  {}", phrase.as_str());
                    println!();
                }
            }
            let w = storage::load_wallet()?;
            println!("network:  {label}");
            println!("identity: {}", tunnel::public_key_hex(&w)?);
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
            println!("{}", tunnel::public_key_hex(&w)?);
            eprintln!("(your identity. a peer pays you with:  cm pay <this>@<your-host:port> <sats>)");
        }
        Some("receive") => {
            let usage = "usage: receive <payer-pubkey-hex> [bind-udp-addr]";
            let peer = args.get(2).ok_or(usage)?;
            let bind = args.get(3).map(String::as_str).unwrap_or("0.0.0.0:51820");
            let w = storage::load_wallet()?;
            tunnel::serve(&w, &storage::ledger_path(&w)?, bind, peer)?;
        }
        Some("pay") => {
            let usage = "usage: pay <peer-pubkey-hex>@<host:port> <sats>";
            let peer = args.get(2).ok_or(usage)?;
            let sats: u64 = args.get(3).ok_or(usage)?.parse()?;
            let (peer_pub, peer_addr) = peer.split_once('@').ok_or(usage)?;
            let w = storage::load_wallet()?;
            tunnel::pay(&w, &storage::ledger_path(&w)?, peer_addr, peer_pub, sats)?;
        }
        Some("demo") => {
            let amount: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(10_000);
            demo::run(amount)?;
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
            let txid = chain::send(&ext, &int, to, sats, policy.max_fee_sats)?;
            led.append(ledger::Entry::Sent {
                seq: led.next_seq(),
                txid: txid.to_string(),
                sats,
                to: to.to_string(),
                status: ledger::Status::Pending,
                at: ledger::now_unix(),
            })?;
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
            eprintln!("  cm id                            print your identity (give it to payers)");
            eprintln!("  cm receive <payer-pubkey> [bind] wait for a payment over WireGuard");
            eprintln!("  cm pay <pubkey@host:port> <sats> pay a peer over WireGuard");
            eprintln!();
            eprintln!("  cm balance                       on-chain balance");
            eprintln!("  cm address [n]                   a receive address (to fund the wallet)");
            eprintln!("  cm send <addr> <sats>            raw on-chain send to an address");
            eprintln!("  cm confs <txid>                  confirmation count for a txid");
            eprintln!("  cm policy                        show the spend policy (limits/fee/blocklist)");
            eprintln!("  cm demo [sats]                   end-to-end payment flow in one process");
            eprintln!("  cm mcp                           stdio MCP server (cm_send, cm_balance) for AI agents");
            eprintln!();
            eprintln!("wallet unlock: encrypted seed (CM_PASSPHRASE) or CM_MNEMONIC for the demo.");
            eprintln!("network: CM_NETWORK = mainnet (default) | testnet | signet.");
            std::process::exit(2);
        }
    }
    Ok(())
}
