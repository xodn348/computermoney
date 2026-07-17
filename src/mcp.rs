//! mcp — an in-process MCP server so an AI agent pays Bitcoin in plain language.
//!
//! `cm mcp` speaks JSON-RPC 2.0 over stdio (the MCP transport): one compact
//! JSON object per line in, one per line out, with every byte of diagnostics
//! routed to stderr so stdout stays a clean protocol stream. The tools give an
//! agent the whole pipeline: `cm_setup` (create/report the wallet + its
//! Silent Payments code), `cm_id` / `cm_address` (identity + funding address),
//! `cm_serve` (run the seller daemon for the session's lifetime), `cm_send`
//! (pay an address, drawing on received SP funds too), `cm_pay` (pay a peer by
//! SP code, card key, or direct wg-pubkey@host:port link), `cm_balance`
//! (on-chain + SP balance), `cm_confs` (confirmations + status),
//! `cm_collections` (received payments, incl. offline SP income), `cm_paywall`
//! (sell one body over HTTP 402), and `cm_fetch` (fetch a URL, auto-paying a
//! 402) — each reusing the exact CLI recipes so the agent path and the human
//! path move money identically. The wallet is unlocked lazily: the server starts (and completes
//! the MCP handshake) even with no wallet available, each tool call retries the
//! unlock until it succeeds, and the unlocked wallet is then held for the
//! process lifetime. Right after the wallet unlocks (at startup or on the first
//! call that unlocks it), a best-effort ledger reconcile heals any Pending
//! entries so every session opens on current chain state. The passphrase is
//! never a tool argument.
//!
//! Hand-rolled on serde_json alone (no rmcp/tokio): the esplora client is
//! blocking, so a synchronous read → dispatch → write loop is the whole server.

use std::error::Error;
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{json, Value};

use crate::{
    chain, discover, fetch, ledger, pay, paywall, policy, scan, serve, storage, tunnel, wallet,
};

/// Set while a `cm_serve` daemon thread is live in this process, so a second
/// cm_serve call is refused instead of racing a duplicate listener + lock.
static SERVING: AtomicBool = AtomicBool::new(false);

/// Set while a `cm_paywall` thread is live in this process, so a second
/// cm_paywall call is refused instead of racing a duplicate listener.
static PAYWALL: AtomicBool = AtomicBool::new(false);

/// MCP protocol version this server implements. We echo back the client's
/// requested version on `initialize` (forward-compatible); this is the
/// fallback advertised when the client omits one.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// Run the stdio MCP server until stdin closes. The wallet is unlocked at
/// most once (via `CM_PASSPHRASE`/`CM_MNEMONIC`) and reused for every call —
/// but a missing wallet must not kill the server: the client marks a dead
/// process "failed to connect" with no explanation, while a live server can
/// return a readable tool error. It also lets a wallet created AFTER the
/// session started (`cm setup`) be picked up on the next call.
pub fn run() -> Result<(), Box<dyn Error>> {
    let mut wallet = match storage::load_wallet() {
        Ok(w) => {
            eprintln!(
                "cm mcp: wallet unlocked on {}; serving cm_setup, cm_id, cm_address, cm_serve, cm_send, cm_pay, cm_balance, cm_confs, cm_collections, cm_paywall, cm_fetch over stdio",
                storage::network_label()
            );
            reconcile_best_effort(&w);
            Some(w)
        }
        Err(e) => {
            eprintln!("cm mcp: no wallet yet ({e}); serving anyway — tool calls will retry the unlock");
            None
        }
    };

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();

    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break; // stdin closed: the client went away
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                // Unparseable input: we can't read an id, so per JSON-RPC the
                // error response carries a null id.
                eprintln!("cm mcp: parse error: {e}");
                write_frame(&mut writer, &error_frame(Value::Null, -32700, "parse error"))?;
                continue;
            }
        };
        // Branch on the presence of "id" FIRST: a message with no id is a
        // notification — run side effects and emit NOTHING, even for unknown
        // methods. Only id-bearing requests get a response or error.
        let Some(id) = msg.get("id").cloned() else {
            eprintln!("cm mcp: notification {}", method_of(&msg));
            continue;
        };
        let frame = dispatch(&mut wallet, id, &msg);
        write_frame(&mut writer, &frame)?;
    }
    Ok(())
}

/// Route an id-bearing request to its handler and return the frame to emit.
fn dispatch(wallet: &mut Option<wallet::Wallet>, id: Value, msg: &Value) -> Value {
    let method = method_of(msg);
    let params = msg.get("params");
    match method {
        "initialize" => result_frame(id, initialize_result(params)),
        "ping" => result_frame(id, json!({})),
        "tools/list" => result_frame(id, tools_list_result()),
        "tools/call" => tools_call(wallet, id, params),
        other => error_frame(id, -32601, &format!("method not found: {other}")),
    }
}

/// `initialize` result: echo the client's protocolVersion (fallback to our
/// constant), advertise the tools capability, and identify the server.
fn initialize_result(params: Option<&Value>) -> Value {
    let version = params
        .and_then(|p| p.get("protocolVersion"))
        .and_then(Value::as_str)
        .unwrap_or(PROTOCOL_VERSION);
    json!({
        "protocolVersion": version,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "computermoney", "version": env!("CARGO_PKG_VERSION") },
        "instructions": INSTRUCTIONS
    })
}

/// Shipped to the client on `initialize` (MCP `instructions`): the first thing a
/// fresh agent reads about cm. Factual and call-first — no marketing — so a
/// model that has never seen cm knows what it is, that the tools need no setup,
/// and why reaching for them is worth it.
const INSTRUCTIONS: &str = "\
computermoney (cm) is a self-custodial Bitcoin wallet for AI agents: send and \
receive real bitcoin with no account, no API key, and no payment processor.\n\
\n\
All tools are self-contained. The wallet, network, and home directory come \
from this server's registration environment, so NEVER set environment variables \
or run shell commands to \"prepare\" cm. Just call the tools directly.\n\
\n\
Flows:\n\
- Get paid: call cm_setup once, share the printed sp code (starts sp1/tsp1); \
payers reach you at it even while you are offline.\n\
- Pay: cm_pay accepts an sp1/tsp1 code, a 64-hex card key, or a \
wg-pubkey@host:port link. The payee may be offline.\n\
- Sell: cm_paywall turns a price + body into a URL whose HTTP 402 response \
carries your payment terms.\n\
- Buy: cm_fetch fetches a URL and, if it answers 402 with cm terms, auto-pays \
within max_sats and returns the content.\n\
\n\
Note: money you receive by silent payment spends like any other funds. cm_pay, \
cm_send, and cm_fetch all draw on it automatically, and cm_balance scans for it \
and shows it (including income not yet spendable), so you never run a separate \
collect step just to see or use money paid to you while offline.\n\
\n\
Why it helps you: when you hit a paid API or dataset, cm_fetch lets you pay \
per-call on the spot and keep going, with no signup, no card, and no human in the loop.";

/// `tools/list` result. Every tool carries a JSON-Schema `inputSchema`;
/// cm_balance's is an explicit empty object (not omitted/null).
fn tools_list_result() -> Value {
    json!({
        "tools": [
            {
                "name": "cm_setup",
                "description": "Create this agent's Bitcoin wallet (if it has none) and report its \
                                network, card key, static sp code, funding address, and balance. \
                                Use this first, once. No setup needed. Call it directly; it is \
                                safe to call anytime, and if a wallet already exists it just \
                                reports it. Share the printed sp code to get paid (payers reach it \
                                even while you are offline). On mainnet the seed is sealed, so \
                                CM_PASSPHRASE must be in the server's registration env.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "cm_pay",
                "description": "Pay a peer <sats> satoshis. Use this to send money when you have a \
                                payee handle. peer accepts any of: an sp1/tsp1 silent-payment code \
                                (on-chain, payee may be offline), a 64-hex card key (resolved on \
                                the DHT; on-chain if the card carries an sp code, else a WireGuard \
                                tunnel), or a wg-pubkey@host:port direct link (tunnel, no DHT). No \
                                setup needed. Call directly; the spend policy is enforced inside. \
                                Draws on both your ordinary funds and any silent-payment income you \
                                have received. Returns the txid and a block-explorer URL.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "peer": {
                            "type": "string",
                            "description": "Payee handle. Any of: an sp1/tsp1 silent-payment code (on-chain, payee may be offline), a 64-hex card key (resolved on the DHT to the payee's card), or a wg-pubkey@host:port link (direct tunnel, no DHT)."
                        },
                        "sats": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Amount to send, in satoshis (100,000,000 sats = 1 BTC)."
                        }
                    },
                    "required": ["peer", "sats"]
                }
            },
            {
                "name": "cm_send",
                "description": "Send <sats> satoshis to a Bitcoin <address>. Use this when you have \
                                a plain address rather than a peer handle. Draws on both ordinary \
                                funds and any silent-payment income you have received, so money \
                                paid to you is spendable here. No setup needed. Call directly; \
                                the spend policy is enforced and the send is recorded in the \
                                signed ledger. Returns the txid and a block-explorer URL.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Destination Bitcoin address (any standard type) on the active network."
                        },
                        "sats": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Amount to send, in satoshis (100,000,000 sats = 1 BTC)."
                        }
                    },
                    "required": ["address", "sats"]
                }
            },
            {
                "name": "cm_fetch",
                "description": "Fetch a URL and auto-pay if it is behind an HTTP 402 paywall. Use \
                                this to buy a paid API response or dataset in one step: a normal \
                                200 is returned as-is; a cm 402 response is paid on-chain within \
                                max_sats and the URL is retried until the content comes back. No \
                                setup needed. Call directly; the spend policy is enforced. \
                                Returns the response body, plus the sats paid and txid when a \
                                payment happened.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "URL to GET. A normal 200 is returned as-is; a cm HTTP 402 is paid automatically within max_sats and then retried."
                        },
                        "max_sats": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Spending cap for an auto-payment triggered by a 402, in satoshis. The fetch pays at most this. Default 10000."
                        }
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "cm_paywall",
                "description": "Sell one body of content for a fixed price over HTTP 402, for the \
                                rest of this session. Use this to charge other agents for a \
                                resource: it returns a URL whose unpaid GET yields a 402 carrying \
                                your sp code and price, and a paid retry (proof = txid) yields the \
                                content. No setup needed. Call directly; the listen address is \
                                auto-detected. The server stops when the session ends.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "price_sats": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Price for one GET of the body, in satoshis. Buyers see this in the 402 terms."
                        },
                        "body": {
                            "type": "string",
                            "description": "The content to sell: the exact bytes returned after a valid payment. Optional; defaults to a short placeholder."
                        },
                        "port": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "TCP port to listen on. Default 8402."
                        }
                    },
                    "required": ["price_sats"]
                }
            },
            {
                "name": "cm_balance",
                "description": "Report the wallet's spendable balance on the active network: \
                                confirmed and pending on-chain funds plus any received \
                                silent-payment income. This scans the chain for offline \
                                silent-payment income as part of the call, so the balance reflects \
                                money paid to your sp code even while you were away, with no separate \
                                collect step. Income received but not yet spendable (fewer than 3 \
                                confirmations) is reported on its own 'incoming' line, so a fresh \
                                payment shows up the moment it is scanned. Use this to check funds \
                                before paying; no setup needed, call it directly.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "cm_collections",
                "description": "Scan the chain for money paid to you and report every received \
                                payment (ordinary deposits and offline silent-payment income) as \
                                JSON. Use this to check 'did anyone pay me?': it books newly \
                                found silent payments before reporting. No setup needed. Call \
                                directly.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "cm_confs",
                "description": "Report a payment's confirmation count and status \
                                (pending/soft/final/failed) for <txid>, and advance the ledger's \
                                recorded status. Use this to check whether a send has settled. No \
                                setup needed. Call directly.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "txid": {
                            "type": "string",
                            "description": "Transaction id (hex) to look up on-chain."
                        }
                    },
                    "required": ["txid"]
                }
            },
            {
                "name": "cm_id",
                "description": "Print this agent's card key (the 64-hex identity a peer resolves \
                                on the DHT to discover and pay you) and its static sp code. Use \
                                this to hand someone a payee handle. No setup needed. Call \
                                directly.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "cm_address",
                "description": "Print the wallet's on-chain funding address (receive index 0). Use \
                                this to top the wallet up from an exchange or faucet. No setup \
                                needed. Call directly.",
                "inputSchema": { "type": "object", "properties": {} }
            },
            {
                "name": "cm_serve",
                "description": "Start the interactive seller daemon in the background for the rest \
                                of this session: publish the card on the DHT, accept WireGuard \
                                tunnels, and watch the chain (including for silent-payment income). \
                                Use this only when you need live peer sessions; for plain \
                                get-paid, cm_setup's sp code is enough and you can stay offline. \
                                The endpoint is auto-detected (override with ep host:port; bind \
                                changes the listen socket, default 0.0.0.0:51820). Stops when the \
                                session ends.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "bind": {
                            "type": "string",
                            "description": "Listen socket for the WireGuard tunnel, host:port. Default 0.0.0.0:51820 (use 127.0.0.1:51820 for localhost-only)."
                        },
                        "ep": {
                            "type": "string",
                            "description": "Endpoint to publish on the DHT card, host:port. Defaults to an auto-detected address; omit to stay dial-out only."
                        }
                    }
                }
            }
        ]
    })
}

/// `tools/call` dispatch. An unknown tool name or missing name is a protocol
/// error (-32602); tool execution failures are returned as `isError` content.
/// The wallet unlock is retried here if startup found none — "no wallet" is a
/// tool-level failure the agent can read and relay, not a dead server.
fn tools_call(wallet: &mut Option<wallet::Wallet>, id: Value, params: Option<&Value>) -> Value {
    let name = params.and_then(|p| p.get("name")).and_then(Value::as_str);
    let args = params.and_then(|p| p.get("arguments"));
    if !matches!(
        name,
        Some("cm_send")
            | Some("cm_pay")
            | Some("cm_fetch")
            | Some("cm_paywall")
            | Some("cm_balance")
            | Some("cm_confs")
            | Some("cm_collections")
            | Some("cm_setup")
            | Some("cm_id")
            | Some("cm_address")
            | Some("cm_serve")
    ) {
        return match name {
            Some(other) => error_frame(id, -32602, &format!("unknown tool: {other}")),
            None => error_frame(id, -32602, "missing tool name"),
        };
    }
    // cm_setup creates the wallet, and cm_serve / cm_paywall each spawn a thread
    // that loads its own — all run before the shared unlock so "no wallet yet"
    // is not fatal here.
    match name {
        Some("cm_setup") => return call_setup(id),
        Some("cm_serve") => return call_serve(id, args),
        Some("cm_paywall") => return call_paywall(id, args),
        _ => {}
    }
    let w = match wallet {
        Some(w) => w,
        None => match storage::load_wallet() {
            Ok(loaded) => {
                eprintln!("cm mcp: wallet unlocked on {}", storage::network_label());
                // First unlock of this session: heal any Pending entries, same
                // as the startup path, so a lazily-unlocked session is current.
                reconcile_best_effort(&loaded);
                wallet.insert(loaded)
            }
            Err(e) => return tool_err(id, &e.to_string()),
        },
    };
    match name {
        Some("cm_send") => call_send(w, id, args),
        Some("cm_pay") => call_pay(w, id, args),
        Some("cm_fetch") => call_fetch(w, id, args),
        Some("cm_confs") => call_confs(w, id, args),
        Some("cm_collections") => call_collections(w, id),
        Some("cm_id") => call_id(w, id),
        Some("cm_address") => call_address(w, id),
        _ => call_balance(w, id),
    }
}

/// cm_setup: create the wallet if the store is empty (the CLI `cm setup`
/// recipe), then report identity + funding info. Runs before the shared
/// unlock because its whole point is to work when no wallet exists yet.
fn call_setup(id: Value) -> Value {
    match setup_report() {
        Ok(text) => tool_ok(id, &text),
        Err(e) => tool_err(id, &e.to_string()),
    }
}

fn setup_report() -> Result<String, Box<dyn Error>> {
    let label = storage::network_label();
    let mut backup: Option<String> = None;
    if storage::wallet_ids().is_empty() {
        let pass = std::env::var("CM_PASSPHRASE").ok();
        if pass.is_none() && label == "mainnet" {
            return Err("mainnet seals the seed: add CM_PASSPHRASE to this MCP server's \
                        env registration, then call cm_setup again"
                .into());
        }
        let (w, phrase) = wallet::Wallet::generate()?;
        let phrase = zeroize::Zeroizing::new(phrase);
        storage::save_new_wallet(&w, phrase.as_str(), pass.as_deref())?;
        // A fresh wallet has no prior income, so pin its first SP scan to the
        // current tip: otherwise offline income older than the lookback window
        // before the first scan would be missed forever.
        scan::anchor_birth(&w);
        backup = Some(phrase.as_str().to_string());
    }
    let w = storage::load_wallet()?;
    let mut out = String::new();
    if let Some(words) = backup {
        out.push_str(&format!(
            "wallet created. BACK UP these 12 words — the only recovery:\n{words}\n\n"
        ));
    }
    out.push_str(&format!(
        "network:  {label}\ncard key: {}\nsp code:  {}  (static — share this; payers reach you even while you are offline)\naddress:  {}",
        discover::card_pubkey_hex(&*w.wg_secret_bytes()?),
        w.sp_code()?,
        w.address(0)?
    ));
    let (ext, int) = w.descriptors();
    if let Ok(b) = chain::balance(&ext, &int) {
        out.push_str(&format!(
            "\nbalance:  {} sats confirmed ({} pending)",
            b.confirmed, b.pending
        ));
    }
    // Publish the card (wg key + sp code, no endpoint) so a collection-only
    // agent is discoverable without running cm_serve. Best-effort: a DHT
    // failure is a note, never a setup failure.
    match publish_card_best_effort(&w) {
        Ok(()) => out.push_str("\ncard published to the DHT (peers can resolve your card key)"),
        Err(e) => {
            eprintln!("cm mcp: cm_setup card publish skipped ({e})");
            out.push_str("\ncard publish skipped (DHT unreachable); your sp code still works");
        }
    }
    Ok(out)
}

/// Put the wallet's card on the DHT with no endpoint: just the WireGuard
/// identity + the static sp code, so the card key resolves to a payable sp code
/// even when the agent never runs a daemon. Used by cm_setup.
fn publish_card_best_effort(w: &wallet::Wallet) -> Result<(), Box<dyn Error>> {
    let card = discover::Card {
        wg: w.id_hex()?,
        ep: Vec::new(),
        sp: Some(w.sp_code()?),
        at: ledger::now_unix(),
    };
    discover::publish(&*w.wg_secret_bytes()?, &card)
}

/// cm_id: the agent's card key and static sp code — read-only key math on the
/// held wallet. Both are payee handles: the card key resolves on the DHT, the
/// sp code is paid directly and works even while this agent is offline.
fn call_id(wallet: &wallet::Wallet, id: Value) -> Value {
    let report = (|| -> Result<String, Box<dyn Error>> {
        Ok(format!(
            "card key: {}\nsp code:  {}  (static — share this; payers reach you even while you are offline)",
            discover::card_pubkey_hex(&*wallet.wg_secret_bytes()?),
            wallet.sp_code()?
        ))
    })();
    match report {
        Ok(text) => tool_ok(id, &text),
        Err(e) => tool_err(id, &e.to_string()),
    }
}

/// cm_address: the wallet's funding address (receive index 0).
fn call_address(wallet: &wallet::Wallet, id: Value) -> Value {
    match wallet.address(0) {
        Ok(a) => tool_ok(id, &a.to_string()),
        Err(e) => tool_err(id, &e.to_string()),
    }
}

/// cm_serve: run the seller daemon (`serve::run` — the exact CLI loop) on a
/// background thread that lives until this MCP process exits with its client
/// session. The endpoint the card advertises is auto-detected unless given,
/// so a user never has to know their address. One daemon per session: a
/// second call reports "already serving" instead of racing the wallet lock.
fn call_serve(id: Value, args: Option<&Value>) -> Value {
    if SERVING.swap(true, Ordering::SeqCst) {
        return tool_ok(id, "already serving in this session");
    }
    let bind = args
        .and_then(|a| a.get("bind"))
        .and_then(Value::as_str)
        .unwrap_or("0.0.0.0:51820")
        .to_string();
    let ep = match args.and_then(|a| a.get("ep")).and_then(Value::as_str) {
        Some(e) => e.to_string(),
        None => auto_endpoint(&bind),
    };
    // Pre-flight the unlock synchronously so a missing wallet is a readable
    // tool error, not a silent dead thread.
    let (card, link) = match storage::load_wallet().and_then(|w| {
        Ok((
            discover::card_pubkey_hex(&*w.wg_secret_bytes()?),
            format!("{}@{ep}", w.id_hex()?),
        ))
    }) {
        Ok(v) => v,
        Err(e) => {
            SERVING.store(false, Ordering::SeqCst);
            return tool_err(id, &e.to_string());
        }
    };
    let bind2 = bind.clone();
    let ep2 = ep.clone();
    std::thread::spawn(move || {
        let result = (|| -> Result<(), Box<dyn Error>> {
            let w = storage::load_wallet()?;
            let ledger_path = storage::ledger_path(&w)?;
            serve::run(&w, &ledger_path, &bind2, vec![ep2])
        })();
        // serve::run never returns Ok; reaching here means it died — release
        // the guard so a retry in this session is possible.
        if let Err(e) = result {
            eprintln!("cm mcp: cm_serve daemon exited: {e}");
        }
        SERVING.store(false, Ordering::SeqCst);
    });
    tool_ok(
        id,
        &format!(
            "serving as card key {card}\nendpoint: {ep} (auto-detected unless you passed one)\n\
             direct link: {link} — a peer holding this link dials you without the DHT\n\
             The daemon publishes the card on the DHT, accepts tunnels, and watches the chain \
             for as long as this session stays open. Poll cm_collections to see payments arrive."
        ),
    )
}

/// The endpoint to advertise when the caller gave none: the primary local
/// interface's address + the bind port. The UDP connect never sends a packet;
/// it just asks the kernel which source address routes out. Falls back to
/// loopback (fine for a one-machine demo) when there is no route at all.
fn auto_endpoint(bind: &str) -> String {
    let port = bind
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(51820);
    let ip = std::net::UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|s| {
            s.connect("8.8.8.8:80").ok()?;
            s.local_addr().ok()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string());
    format!("{ip}:{port}")
}

/// Default 402 auto-pay ceiling for cm_fetch when the caller omits max_sats.
const DEFAULT_MAX_SATS: u64 = 10_000;
/// Default body cm_paywall sells when the caller omits one.
const DEFAULT_PAYWALL_BODY: &str =
    "cm paywall: payment received. (Pass body to sell your own content.)\n";

/// cm_fetch: GET a URL, auto-paying a cm 402 up to max_sats. The wallet is
/// already unlocked by `tools_call`; the ledger funds and gates the payment.
fn call_fetch(wallet: &wallet::Wallet, id: Value, args: Option<&Value>) -> Value {
    let Some(args) = args else {
        return error_frame(id, -32602, "cm_fetch requires arguments { url, max_sats? }");
    };
    let Some(url) = args.get("url").and_then(Value::as_str) else {
        return error_frame(id, -32602, "cm_fetch: 'url' must be a string");
    };
    let max_sats = args
        .get("max_sats")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_MAX_SATS);
    match fetch_report(wallet, url, max_sats) {
        Ok(text) => tool_ok(id, &text),
        Err(e) => tool_err(id, &e.to_string()),
    }
}

fn fetch_report(wallet: &wallet::Wallet, url: &str, max_sats: u64) -> Result<String, Box<dyn Error>> {
    let mut led = open_ledger(wallet)?;
    eprintln!("cm mcp: cm_fetch {url} (auto-pay up to {max_sats} sats)…");
    let out = fetch::fetch(wallet, &mut led, url, max_sats)?;
    match out.paid {
        Some((txid, sats)) => Ok(format!(
            "paid {sats} sats, txid {txid}\n{}\n\n{}",
            storage::explorer_tx_url(&txid),
            out.body
        )),
        None => Ok(out.body),
    }
}

/// cm_paywall: run the HTTP 402 seller (`paywall::run` — the exact CLI loop) on
/// a background thread that lives until this MCP process exits with its client
/// session. The listen IP is auto-detected so a user never has to know their
/// address. One paywall per session: a second call reports "already running".
fn call_paywall(id: Value, args: Option<&Value>) -> Value {
    let price_sats = match args.and_then(|a| a.get("price_sats")).and_then(Value::as_u64) {
        Some(p) if p >= 1 => p,
        _ => return error_frame(id, -32602, "cm_paywall: 'price_sats' must be a positive integer"),
    };
    let body = args
        .and_then(|a| a.get("body"))
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_PAYWALL_BODY)
        .to_string();
    let port = args
        .and_then(|a| a.get("port"))
        .and_then(Value::as_u64)
        .unwrap_or(8402) as u16;
    let bind = format!("0.0.0.0:{port}");

    if PAYWALL.swap(true, Ordering::SeqCst) {
        return tool_ok(id, "already running a paywall in this session");
    }
    // Pre-flight synchronously so a failure is a readable tool error, not a
    // silent dead thread: unlock the wallet, read the sp code, and BIND the
    // listener here — a port conflict must fail the call, not leave the agent
    // told it is serving on a URL nothing listens to.
    let (sp_code, listener) = match (|| -> Result<(String, std::net::TcpListener), Box<dyn Error>> {
        let w = storage::load_wallet()?;
        let code = w.sp_code()?;
        let listener = std::net::TcpListener::bind(&bind)?;
        Ok((code, listener))
    })() {
        Ok(v) => v,
        Err(e) => {
            PAYWALL.store(false, Ordering::SeqCst);
            return tool_err(id, &format!("cm_paywall could not bind {bind}: {e}"));
        }
    };
    let url = format!("http://{}", auto_endpoint(&bind));
    std::thread::spawn(move || {
        let result = (|| -> Result<(), Box<dyn Error>> {
            let w = storage::load_wallet()?;
            paywall::run(listener, price_sats, body, &w)
        })();
        // paywall::run only returns on an accept error; release the guard so a
        // retry in this session is possible.
        if let Err(e) = result {
            eprintln!("cm mcp: cm_paywall exited: {e}");
        }
        PAYWALL.store(false, Ordering::SeqCst);
    });
    tool_ok(
        id,
        &format!(
            "serving content at {url} for {price_sats} sats\n\
             any GET gets a 402 asking {price_sats} sats to your sp code ({sp_code}); \
             a paid retry (header X-Payment: <txid>) gets the content.\n\
             The paywall runs for as long as this session stays open."
        ),
    )
}

/// Best-effort ledger reconcile on the just-unlocked wallet: open the signed
/// ledger and advance any Pending payment against the chain (the same
/// `ledger::reconcile` recipe `net::run_receiver` runs). Never fatal — a
/// chain-unreachable or ledger error is logged and swallowed so a failed heal
/// can't stop the server from serving.
fn reconcile_best_effort(wallet: &wallet::Wallet) {
    match reconcile_ledger(wallet) {
        Ok(n) => eprintln!("cm mcp: startup reconcile advanced {n} ledger entr(ies)"),
        Err(e) => eprintln!("cm mcp: startup reconcile skipped ({e})"),
    }
}

/// Open the signed ledger and reconcile it against the chain, returning how
/// many entries advanced. Shared by the startup heal and cm_confs.
fn reconcile_ledger(wallet: &wallet::Wallet) -> Result<usize, Box<dyn Error>> {
    let mut led = ledger::Ledger::open_with_identity(
        storage::ledger_path(wallet)?,
        wallet.signing_keypair()?,
    )?;
    ledger::reconcile(&mut led)
}

/// cm_send: validate arguments (protocol-level on failure), then run the send
/// recipe (tool-level on failure — policy reject / chain unreachable).
fn call_send(wallet: &wallet::Wallet, id: Value, args: Option<&Value>) -> Value {
    let Some(args) = args else {
        return error_frame(id, -32602, "cm_send requires arguments { address, sats }");
    };
    let Some(to) = args.get("address").and_then(Value::as_str) else {
        return error_frame(id, -32602, "cm_send: 'address' must be a string");
    };
    let Some(sats) = args.get("sats").and_then(Value::as_u64) else {
        return error_frame(id, -32602, "cm_send: 'sats' must be a positive integer");
    };
    if sats == 0 {
        return error_frame(id, -32602, "cm_send: 'sats' must be >= 1");
    }
    match send_payment(wallet, to, sats) {
        Ok(text) => tool_ok(id, &text),
        Err(e) => tool_err(id, &e.to_string()),
    }
}

/// The exact `cm send` recipe (main.rs send arm) on the held wallet: open the
/// signed ledger, gate on policy (amount + blocklist), then hand off to
/// `pay::send`, which records the Sent entry durably BEFORE broadcasting (the
/// mainnet guard runs inside the build step). Returns the human text the agent
/// reads back.
fn send_payment(wallet: &wallet::Wallet, to: &str, sats: u64) -> Result<String, Box<dyn Error>> {
    let mut led =
        ledger::Ledger::open_with_identity(storage::ledger_path(wallet)?, wallet.signing_keypair()?)?;
    let policy = policy::Policy::load()?;
    let spent = led.spent_since(ledger::now_unix().saturating_sub(policy::DAILY_WINDOW_SECS));
    policy.check_amount(sats, spent)?;
    policy.check_address(to)?;
    let (ext, int) = wallet.descriptors();
    eprintln!("cm mcp: cm_send {sats} sats -> {to}: syncing + building + broadcasting…");
    // send_spending_sp draws on received silent-payment outputs as well as
    // descriptor UTXOs, so income paid to us is spendable here; with no SP
    // funds it behaves exactly like pay::send.
    let txid = pay::send_spending_sp(&mut led, wallet, &ext, &int, to, sats, policy.max_fee_sats)?;
    Ok(format!(
        "txid: {txid}\n{}",
        storage::explorer_tx_url(&txid)
    ))
}

/// cm_balance: sync the descriptors from esplora and report confirmed/pending
/// on the active network. A chain-unreachable error is a tool-level failure.
fn call_balance(wallet: &wallet::Wallet, id: Value) -> Value {
    match balance_report(wallet) {
        Ok(text) => tool_ok(id, &text),
        Err(e) => tool_err(id, &e.to_string()),
    }
}

fn balance_report(wallet: &wallet::Wallet) -> Result<String, Box<dyn Error>> {
    let (ext, int) = wallet.descriptors();
    eprintln!("cm mcp: cm_balance: syncing from {}…", storage::network_label());
    let b = chain::balance(&ext, &int)?;
    // Silent-payment income lands on one-time addresses the descriptors can't
    // know, so a plain sync misses it. Scan the chain for it and advance its
    // confirmations here, both best-effort: any failure falls back to income
    // already booked and never fails the balance. This folds what cm_collections
    // does into cm_balance so a single balance call reflects offline SP income.
    let (sp, sp_incoming) = match open_ledger(wallet) {
        Ok(mut led) => {
            if let Err(e) = scan::scan_to_tip(wallet, &mut led) {
                eprintln!("cm mcp: cm_balance: sp scan skipped ({e})");
            }
            if let Err(e) = ledger::reconcile(&mut led) {
                eprintln!("cm mcp: cm_balance: sp reconcile skipped ({e})");
            }
            (led.sp_balance(), led.sp_incoming())
        }
        Err(_) => (0, 0),
    };
    let sp_line = if sp > 0 {
        format!(" (+{sp} sats silent-payment income, spendable like any funds)")
    } else {
        String::new()
    };
    // Fresh SP income shows here the instant it is scanned, before it reaches
    // 3 confirmations and moves into the spendable line above.
    let incoming_line = if sp_incoming > 0 {
        format!(
            "\nincoming: {sp_incoming} sats silent-payment income (received, not yet spendable — 3 confirmations away)"
        )
    } else {
        String::new()
    };
    Ok(format!(
        "network: {}\nconfirmed: {} sats{}\npending: {} sats{}",
        storage::network_label(),
        b.confirmed,
        sp_line,
        b.pending,
        incoming_line
    ))
}

/// Open this wallet's signed ledger for a read fold. Shared by the balance and
/// collections reports.
fn open_ledger(wallet: &wallet::Wallet) -> Result<ledger::Ledger, Box<dyn Error>> {
    Ok(ledger::Ledger::open_with_identity(
        storage::ledger_path(wallet)?,
        wallet.signing_keypair()?,
    )?)
}

/// cm_pay: validate arguments (protocol-level on failure), then run the pay
/// recipe (tool-level on failure — no card / no endpoint / policy reject / chain
/// unreachable). The wallet is already unlocked by `tools_call`.
fn call_pay(wallet: &wallet::Wallet, id: Value, args: Option<&Value>) -> Value {
    let Some(args) = args else {
        return error_frame(id, -32602, "cm_pay requires arguments { peer, sats }");
    };
    let Some(peer) = args.get("peer").and_then(Value::as_str) else {
        return error_frame(
            id,
            -32602,
            "cm_pay: 'peer' must be a string (a 64-hex card key, or wg-pubkey@host:port)",
        );
    };
    let Some(sats) = args.get("sats").and_then(Value::as_u64) else {
        return error_frame(id, -32602, "cm_pay: 'sats' must be a positive integer");
    };
    if sats == 0 {
        return error_frame(id, -32602, "cm_pay: 'sats' must be >= 1");
    }
    match pay_peer(wallet, peer, sats) {
        Ok(text) => tool_ok(id, &text),
        Err(e) => tool_err(id, &e.to_string()),
    }
}

/// The full `cm pay` recipe (both main.rs arms) on the held wallet. A peer
/// with an `@` is a direct link `wg-pubkey@host:port` — dial it straight, no
/// DHT. Otherwise it is a card key: resolve the card on the DHT, then open a
/// WireGuard tunnel to each published endpoint in turn. Both settle via
/// `tunnel::pay`. The spend policy (amount cap + OFAC address blocklist) is NOT
/// re-checked here on purpose: it already runs inside the pay path
/// (`net::run_payer`, invoked by `tunnel::pay`), so duplicating it would be
/// redundant and a second copy to keep in sync. `tunnel::pay` returns `()`, so
/// the settled txid is read back from the ledger's most recent Sent entry to
/// build the returned txid + explorer URL.
fn pay_peer(wallet: &wallet::Wallet, peer: &str, sats: u64) -> Result<String, Box<dyn Error>> {
    let ledger_path = storage::ledger_path(wallet)?;
    let peer = peer.trim();
    // A Silent Payments code pays on-chain with no tunnel — the payee may be
    // offline. Return directly with the txid sp_send produced.
    if peer.starts_with("sp1") || peer.starts_with("tsp1") {
        eprintln!("cm mcp: cm_pay sending {sats} sats to an sp code (on-chain, no tunnel)…");
        let txid = sp_pay(wallet, peer, sats)?;
        return Ok(format!("txid: {txid}\n{}", storage::explorer_tx_url(&txid)));
    }
    if let Some((peer_pub, peer_addr)) = peer.split_once('@') {
        eprintln!("cm mcp: cm_pay dialing {peer_pub} @ {peer_addr} (direct link, no DHT)…");
        tunnel::pay(wallet, &ledger_path, peer_addr, peer_pub, sats)?;
    } else {
        let key = discover::parse_card_key(peer)?;
        eprintln!("cm mcp: cm_pay resolving card {}… (DHT)", &peer[..8]);
        let card = discover::resolve(&key)?.ok_or("no card on the DHT for that key")?;
        // Prefer the card's sp code when present: on-chain, no tunnel, and the
        // peer need not be online. Fall back to the WireGuard tunnel otherwise.
        if let Some(code) = card.sp.as_deref() {
            eprintln!("cm mcp: card carries an sp code — paying on-chain, no tunnel…");
            let txid = sp_pay(wallet, code, sats)?;
            return Ok(format!("txid: {txid}\n{}", storage::explorer_tx_url(&txid)));
        }
        if card.ep.is_empty() {
            return Err("peer published no endpoint (not accepting inbound sessions)".into());
        }
        // Try each published endpoint (v4, v6, …) in order until one session
        // succeeds; if all fail, surface the last error.
        let mut last_err = None;
        for addr in &card.ep {
            eprintln!("cm mcp: cm_pay dialing {} @ {addr}…", card.wg);
            match tunnel::pay(wallet, &ledger_path, addr, &card.wg, sats) {
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
    // tunnel::pay recorded the Sent entry before broadcasting; read the newest
    // one back for its txid (the pay path does not return it).
    let led = ledger::Ledger::open_with_identity(&ledger_path, wallet.signing_keypair()?)?;
    let txid = led
        .entries()
        .iter()
        .rev()
        .find_map(|e| match e {
            ledger::Entry::Sent { txid, .. } => Some(txid.clone()),
            _ => None,
        })
        .ok_or("payment sent but no Sent entry found in the ledger")?;
    Ok(format!("txid: {txid}\n{}", storage::explorer_tx_url(&txid)))
}

/// Pay a Silent Payments code on-chain. The tunnel path gates the spend policy
/// inside `net::run_payer`, but the SP path does not, so gate it here (amount +
/// blocklist on the payee handle) before handing off to `pay::sp_send`. The
/// blocklist matches the sp code, not the on-chain destination — a silent
/// payment's address is one-time and cannot be pre-listed, so operators block an
/// unwanted payee by its sp code; `pay::sp_send` additionally checks the derived
/// address as a uniform backstop.
fn sp_pay(wallet: &wallet::Wallet, code: &str, sats: u64) -> Result<String, Box<dyn Error>> {
    let mut led = ledger::Ledger::open_with_identity(
        storage::ledger_path(wallet)?,
        wallet.signing_keypair()?,
    )?;
    let policy = policy::Policy::load()?;
    let spent = led.spent_since(ledger::now_unix().saturating_sub(policy::DAILY_WINDOW_SECS));
    policy.check_amount(sats, spent)?;
    policy.check_address(code)?;
    let (ext, int) = wallet.descriptors();
    pay::sp_send(&mut led, wallet, &ext, &int, code, sats, policy.max_fee_sats)
}

/// cm_confs: validate the txid argument, then report the payment's confirmation
/// count and status label and reconcile the ledger so its status advances.
fn call_confs(wallet: &wallet::Wallet, id: Value, args: Option<&Value>) -> Value {
    let Some(args) = args else {
        return error_frame(id, -32602, "cm_confs requires arguments { txid }");
    };
    let Some(txid) = args.get("txid").and_then(Value::as_str) else {
        return error_frame(id, -32602, "cm_confs: 'txid' must be a string");
    };
    match confs_report(wallet, txid) {
        Ok(text) => tool_ok(id, &text),
        Err(e) => tool_err(id, &e.to_string()),
    }
}

/// Ask the chain for `txid`'s confirmation count, map it to the locked status
/// label, then reconcile the ledger so this (and any other pending) entry
/// advances. The returned count/label is the direct chain answer; the reconcile
/// is the durable side effect that lets `cm_collections`/balance reflect it.
fn confs_report(wallet: &wallet::Wallet, txid: &str) -> Result<String, Box<dyn Error>> {
    eprintln!("cm mcp: cm_confs {txid}: querying {}…", storage::network_label());
    let confs = chain::confirmations(txid)?;
    let label = status_label(ledger::Status::from_confirmations(confs));
    // Advance the ledger; a reconcile failure must not hide the count we have.
    if let Err(e) = reconcile_ledger(wallet) {
        eprintln!("cm mcp: cm_confs reconcile skipped ({e})");
    }
    Ok(format!("txid: {txid}\nconfirmations: {confs}\nstatus: {label}"))
}

/// cm_collections: scan for offline silent-payment income, then report receive
/// state as a JSON object `{ scan, collections[] }`. `scan` is a one-line note
/// on the scan pass; each `collections` row is either a descriptor receive
/// (`type:"receive"` with `index` + `address`) or a silent payment
/// (`type:"sp"` with `outpoint`), plus `status` (awaiting|paid), `sats`, and a
/// `txid` once bound. The seller's agent polls this to know a payment arrived.
fn call_collections(wallet: &wallet::Wallet, id: Value) -> Value {
    match collections_report(wallet) {
        Ok(text) => tool_ok(id, &text),
        Err(e) => tool_err(id, &e.to_string()),
    }
}

fn collections_report(wallet: &wallet::Wallet) -> Result<String, Box<dyn Error>> {
    let mut led = open_ledger(wallet)?;
    // Scan the chain for offline silent-payment income first, best-effort: a
    // scan failure becomes a note in the reply, never an error — the ledger
    // rows we already have still report.
    let scan_note = match scan::scan_to_tip(wallet, &mut led) {
        Ok(r) => format!(
            "scanned blocks {}..{}, {} new silent payment(s)",
            r.from_height,
            r.to_height,
            r.found.len()
        ),
        Err(e) => format!("silent-payment scan skipped ({e}); reporting known payments only"),
    };
    let mut rows = Vec::new();
    for c in led.collections() {
        // A row is "paid" once a txid is bound (a Received for a descriptor
        // address, or the receiving tx for a silent payment), else it is still
        // "awaiting" the on-chain deposit.
        let status = if c.txid.is_some() { "paid" } else { "awaiting" };
        let row = if c.sp {
            // Silent-payment receipt: `index` is the output's vout, and there is
            // no issued address — render the outpoint, never wallet.address().
            json!({
                "type": "sp",
                "outpoint": format!("{}:{}", c.txid.clone().unwrap_or_default(), c.index),
                "status": status,
                "sats": c.sats,
                "txid": c.txid,
            })
        } else {
            let mut row = json!({
                "type": "receive",
                "index": c.index,
                "address": wallet.address(c.index)?.to_string(),
                "status": status,
                "sats": c.sats,
            });
            if let Some(txid) = c.txid {
                row["txid"] = json!(txid);
            }
            row
        };
        rows.push(row);
    }
    Ok(serde_json::to_string_pretty(&json!({
        "scan": scan_note,
        "collections": rows,
    }))?)
}

/// The lowercase status word for a confirmation stage. `from_confirmations`
/// only yields pending/soft/final, but `Failed` is mapped too so this stays a
/// total function over `Status`.
fn status_label(status: ledger::Status) -> &'static str {
    match status {
        ledger::Status::Pending => "pending",
        ledger::Status::Soft => "soft",
        ledger::Status::Final => "final",
        ledger::Status::Failed => "failed",
    }
}

// --- JSON-RPC framing helpers. Every frame carries `jsonrpc: "2.0"`. ---

/// A successful response frame.
fn result_frame(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

/// A JSON-RPC error frame (protocol-level failure).
fn error_frame(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// A tools/call success result (isError: false).
fn tool_ok(id: Value, text: &str) -> Value {
    result_frame(
        id,
        json!({ "content": [{ "type": "text", "text": text }], "isError": false }),
    )
}

/// A tools/call failure result (isError: true) — the reason is readable text,
/// not a protocol error, so the agent can react to it.
fn tool_err(id: Value, text: &str) -> Value {
    result_frame(
        id,
        json!({ "content": [{ "type": "text", "text": text }], "isError": true }),
    )
}

/// Write one compact JSON frame followed by a newline, then flush — stdout is
/// the JSON-RPC stream and the client reads line by line.
fn write_frame(w: &mut impl Write, frame: &Value) -> std::io::Result<()> {
    let line = serde_json::to_string(frame).unwrap_or_else(|_| "{}".to_string());
    w.write_all(line.as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()
}

/// The request's method, or a placeholder for logging.
fn method_of(msg: &Value) -> &str {
    msg.get("method").and_then(Value::as_str).unwrap_or("(none)")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The status label is the lowercase word for each stage — the strings the
    /// cm_confs contract promises (pending/soft/final/failed).
    #[test]
    fn status_label_words() {
        assert_eq!(status_label(ledger::Status::Pending), "pending");
        assert_eq!(status_label(ledger::Status::Soft), "soft");
        assert_eq!(status_label(ledger::Status::Final), "final");
        assert_eq!(status_label(ledger::Status::Failed), "failed");
        // The label matches what the confirmation ladder maps to, end to end.
        assert_eq!(status_label(ledger::Status::from_confirmations(0)), "pending");
        assert_eq!(status_label(ledger::Status::from_confirmations(1)), "soft");
        assert_eq!(status_label(ledger::Status::from_confirmations(3)), "final");
    }

    /// The `-32602` protocol code carried by a frame, if it is an error frame.
    fn err_code(frame: &Value) -> Option<i64> {
        frame.get("error").and_then(|e| e.get("code")).and_then(Value::as_i64)
    }

    // A wallet is needed to type-check these calls, but every case here rejects
    // the arguments and returns BEFORE the wallet is touched — no network.
    fn test_wallet() -> wallet::Wallet {
        wallet::Wallet::generate().unwrap().0
    }

    #[test]
    fn cm_pay_rejects_bad_arguments() {
        let w = test_wallet();
        // Missing arguments object.
        assert_eq!(err_code(&call_pay(&w, json!(1), None)), Some(-32602));
        // peer not a string.
        let args = json!({ "sats": 1000 });
        assert_eq!(err_code(&call_pay(&w, json!(1), Some(&args))), Some(-32602));
        // sats missing / not a positive integer.
        let args = json!({ "peer": "ab" });
        assert_eq!(err_code(&call_pay(&w, json!(1), Some(&args))), Some(-32602));
        // sats == 0 is rejected before any resolve or dial.
        let args = json!({ "peer": "ab", "sats": 0 });
        assert_eq!(err_code(&call_pay(&w, json!(1), Some(&args))), Some(-32602));
    }

    #[test]
    fn cm_confs_rejects_bad_arguments() {
        let w = test_wallet();
        assert_eq!(err_code(&call_confs(&w, json!(1), None)), Some(-32602));
        let args = json!({ "txid": 123 }); // not a string
        assert_eq!(err_code(&call_confs(&w, json!(1), Some(&args))), Some(-32602));
    }

    #[test]
    fn unknown_tool_is_a_protocol_error() {
        let mut wallet = None;
        let params = json!({ "name": "cm_bogus", "arguments": {} });
        assert_eq!(err_code(&tools_call(&mut wallet, json!(1), Some(&params))), Some(-32602));
        let params = json!({ "arguments": {} }); // missing name
        assert_eq!(err_code(&tools_call(&mut wallet, json!(1), Some(&params))), Some(-32602));
    }
}
