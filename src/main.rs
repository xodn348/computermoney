//! computermoney — milestone 1 CLI.
//!
//! Build ladder step 1: turn a mnemonic into a signet Taproot address.
//! No tunnel, no chain sync yet — just the wallet root the rest builds on.

mod chain;
mod discover;
mod fetch;
mod ledger;
mod mcp;
mod net;
mod pay;
mod paywall;
mod policy;
mod protocol;
mod scan;
mod serve;
mod sp;
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

/// Pay a Silent Payments code from the CLI: gate the standing spend policy
/// (amount cap + blocklist on the payee handle), then send on-chain via
/// `pay::sp_send`. Returns the txid. The tunnel path gates inside
/// `net::run_payer`; the SP path does not, so the check lives here. The
/// blocklist matches the sp code, not the one-time on-chain address (which
/// cannot be pre-listed); `pay::sp_send` also checks the derived address.
fn cli_sp_pay(w: &Wallet, code: &str, sats: u64) -> Result<String, Box<dyn std::error::Error>> {
    let mut led =
        ledger::Ledger::open_with_identity(storage::ledger_path(w)?, w.signing_keypair()?)?;
    let pol = policy::Policy::load()?;
    let spent = led.spent_since(ledger::now_unix().saturating_sub(policy::DAILY_WINDOW_SECS));
    pol.check_amount(sats, spent)?;
    pol.check_address(code)?;
    let (ext, int) = w.descriptors();
    pay::sp_send(&mut led, w, &ext, &int, code, sats, pol.max_fee_sats)
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
                // Pin the first SP scan to the current tip: a fresh wallet has no
                // prior income, and this keeps later offline income findable.
                scan::anchor_birth(&w);
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
            println!("card key: {}", discover::card_pubkey_hex(&*w.wg_secret_bytes()?));
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
            // Scan the chain for silent-payment income (one-time addresses the
            // descriptors can't know) and advance its confirmations, both
            // best-effort, so `cm balance` alone reflects offline SP income.
            let (sp, sp_incoming) = match ledger::Ledger::open_with_identity(
                storage::ledger_path(&w)?,
                w.signing_keypair()?,
            ) {
                Ok(mut led) => {
                    if let Err(e) = scan::scan_to_tip(&w, &mut led) {
                        eprintln!("silent-payment scan skipped ({e})");
                    }
                    if let Err(e) = ledger::reconcile(&mut led) {
                        eprintln!("silent-payment reconcile skipped ({e})");
                    }
                    (led.sp_balance(), led.sp_incoming())
                }
                Err(_) => (0, 0),
            };
            println!("network:   {}", storage::network_label());
            if sp > 0 {
                println!(
                    "confirmed: {} sats (+{sp} sats silent-payment income, spendable like any funds)",
                    b.confirmed
                );
            } else {
                println!("confirmed: {} sats", b.confirmed);
            }
            println!("pending:   {} sats", b.pending);
            // Fresh SP income appears here the instant it is scanned, before it
            // reaches 3 confirmations and becomes spendable above.
            if sp_incoming > 0 {
                println!(
                    "incoming:  {sp_incoming} sats silent-payment income (received, not yet spendable — 3 confirmations away)"
                );
            }
        }
        Some("id") => {
            let w = storage::load_wallet()?;
            let card = discover::card_pubkey_hex(&*w.wg_secret_bytes()?);
            println!("{card}");
            println!("sp code: {}", w.sp_code()?);
            eprintln!("(card key: resolve-and-pay handle. sp code: static, pays you even offline.");
            eprintln!(" publish where to reach you with `cm publish <your-host:port>`.)");
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
                sp: Some(w.sp_code()?),
                at: ledger::now_unix(),
            };
            eprintln!("publishing card to the DHT…");
            discover::publish(&*w.wg_secret_bytes()?, &card)?;
            let card_key = discover::card_pubkey_hex(&*w.wg_secret_bytes()?);
            if card.ep.is_empty() {
                println!("published: {card_key} (no endpoint — dial-out only)");
            } else {
                println!("published: {card_key} @ {}", card.ep.join(", "));
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
            let usage = "usage: pay <sp-code | card-key | pubkey@host:port> <sats>";
            let peer = args.get(2).ok_or(usage)?.trim().to_string();
            let sats: u64 = args.get(3).ok_or(usage)?.parse()?;
            let w = storage::load_wallet()?;
            if peer.starts_with("sp1") || peer.starts_with("tsp1") {
                // Silent-payment code: on-chain, no tunnel, payee may be offline.
                let txid = cli_sp_pay(&w, &peer, sats)?;
                println!("txid: {txid}");
                println!("{}", storage::explorer_tx_url(&txid));
            } else if let Some((peer_pub, peer_addr)) = peer.split_once('@') {
                tunnel::pay(&w, &storage::ledger_path(&w)?, peer_addr, peer_pub, sats)?;
            } else {
                let key = discover::parse_card_key(&peer)?;
                eprintln!("resolving card {}… (DHT)", &peer[..8]);
                let card = discover::resolve(&key)?
                    .ok_or("no card found on the DHT for that key")?;
                // Prefer the card's sp code when present: on-chain, no tunnel,
                // and the peer need not be online.
                if let Some(code) = card.sp.as_deref() {
                    eprintln!("card carries an sp code — paying on-chain, no tunnel…");
                    let txid = cli_sp_pay(&w, code, sats)?;
                    println!("txid: {txid}");
                    println!("{}", storage::explorer_tx_url(&txid));
                } else {
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
        Some("fetch") => {
            // Buy: GET a URL and auto-pay a cm HTTP 402 within the cap.
            let usage = "usage: fetch <url> [--max-sats N]";
            let url = args.get(2).ok_or(usage)?.clone();
            let mut max_sats = 10_000u64;
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--max-sats" => {
                        max_sats = args.get(i + 1).ok_or("--max-sats needs a number")?.parse()?;
                        i += 2;
                    }
                    other => return Err(format!("unknown fetch argument: {other}").into()),
                }
            }
            let w = storage::load_wallet()?;
            let mut led = ledger::Ledger::open_with_identity(
                storage::ledger_path(&w)?,
                w.signing_keypair()?,
            )?;
            let out = fetch::fetch(&w, &mut led, &url, max_sats)?;
            if let Some((txid, sats)) = out.paid {
                eprintln!("paid {sats} sats (txid {txid})");
            }
            eprintln!("HTTP {} ({} bytes)", out.status, out.body.len());
            print!("{}", out.body);
        }
        Some("paywall") => {
            // Sell: serve one body for a fixed price over HTTP 402 (blocking).
            let usage = "usage: paywall <price_sats> [--port N] [--body S]";
            let price_sats: u64 = args.get(2).ok_or(usage)?.parse()?;
            let mut port = 8402u16;
            let mut body = "cm paywall: payment received.\n".to_string();
            let mut i = 3;
            while i < args.len() {
                match args[i].as_str() {
                    "--port" => {
                        port = args.get(i + 1).ok_or("--port needs a number")?.parse()?;
                        i += 2;
                    }
                    "--body" => {
                        body = args.get(i + 1).ok_or("--body needs a string")?.clone();
                        i += 2;
                    }
                    other => return Err(format!("unknown paywall argument: {other}").into()),
                }
            }
            let w = storage::load_wallet()?;
            // Bind here so a port conflict is an immediate CLI error.
            let bind = format!("0.0.0.0:{port}");
            let listener = std::net::TcpListener::bind(&bind)
                .map_err(|e| format!("could not bind {bind}: {e}"))?;
            paywall::run(listener, price_sats, body, &w)?;
        }
        Some("confs") => {
            // A quick, stateless confirmation check for any txid: the signal the
            // `cm pay` success line points at, needing no wallet unlock.
            let txid = args.get(2).ok_or("usage: confs <txid>")?;
            let confs = chain::confirmations(txid)?;
            let status = match ledger::Status::from_confirmations(confs) {
                ledger::Status::Pending => "pending",
                ledger::Status::Soft => "soft",
                ledger::Status::Final => "final",
                ledger::Status::Failed => "failed",
            };
            println!("txid:          {txid}");
            println!("confirmations: {confs}");
            println!("status:        {status}");
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
            eprintln!("  cm pay <sp-code> <sats>          pay a silent-payment code on-chain (payee may be offline)");
            eprintln!("  cm pay <card-key> <sats>         discover -> talk -> settle, in one command");
            eprintln!("  cm pay <pubkey@host:port> <sats> pay a known endpoint directly (no DHT)");
            eprintln!("  cm fetch <url> [--max-sats N]    GET a URL, auto-paying a cm HTTP 402");
            eprintln!("  cm paywall <price> [--port N] [--body S]  sell one body over HTTP 402 (blocking)");
            eprintln!("  cm balance                       on-chain + silent-payment balance");
            eprintln!("  cm confs <txid>                  confirmation count + status (pending/soft/final)");
            eprintln!("  cm mcp                           stdio MCP server for AI agents (11 tools: pay/send/fetch/paywall/…)");
            eprintln!();
            eprintln!("wallet unlock: encrypted seed (CM_PASSPHRASE) or the stored mnemonic; CM_MNEMONIC overrides.");
            eprintln!("network: CM_NETWORK = mainnet (default) | testnet | signet.");
            std::process::exit(2);
        }
    }
    Ok(())
}
