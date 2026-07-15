//! mcp — an in-process MCP server so an AI agent pays Bitcoin in plain language.
//!
//! `cm mcp` speaks JSON-RPC 2.0 over stdio (the MCP transport): one compact
//! JSON object per line in, one per line out, with every byte of diagnostics
//! routed to stderr so stdout stays a clean protocol stream. The tools give an
//! agent the whole pipeline — `cm_send` (broadcast to an address), `cm_pay`
//! (discover a peer by card key, tunnel, settle), `cm_balance` (on-chain
//! balance), `cm_confs` (a payment's confirmations + status) and
//! `cm_collections` (per-index receive state the seller polls) — each reusing
//! the exact CLI recipes so the agent path and the human path move money
//! identically. The wallet is unlocked lazily: the server starts (and completes
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

use serde_json::{json, Value};

use crate::{chain, discover, ledger, policy, storage, tunnel, wallet};

/// MCP protocol version this server implements. We echo back the client's
/// requested version on `initialize` (forward-compatible); this is the
/// fallback advertised when the client omits one.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// Run the stdio MCP server until stdin closes. The wallet is unlocked at
/// most once (via `CM_PASSPHRASE`/`CM_MNEMONIC`) and reused for every call —
/// but a missing wallet must not kill the server: the client marks a dead
/// process "failed to connect" with no explanation, while a live server can
/// return a readable tool error. It also lets a wallet created AFTER the
/// session started (`cm init` / `cm setup`) be picked up on the next call.
pub fn run() -> Result<(), Box<dyn Error>> {
    let mut wallet = match storage::load_wallet() {
        Ok(w) => {
            eprintln!(
                "cm mcp: wallet unlocked on {}; serving cm_send, cm_pay, cm_balance, cm_confs, cm_collections over stdio",
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
        "serverInfo": { "name": "computermoney", "version": env!("CARGO_PKG_VERSION") }
    })
}

/// `tools/list` result. Every tool carries a JSON-Schema `inputSchema`;
/// cm_balance's is an explicit empty object (not omitted/null).
fn tools_list_result() -> Value {
    json!({
        "tools": [
            {
                "name": "cm_send",
                "description": "Broadcast a Bitcoin payment of <sats> satoshis to <address>. \
                                Enforces the local spend policy and records the send in the \
                                signed ledger. Returns the txid and a block-explorer URL.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "address": { "type": "string" },
                        "sats": { "type": "integer", "minimum": 1 }
                    },
                    "required": ["address", "sats"]
                }
            },
            {
                "name": "cm_pay",
                "description": "Pay a peer discovered by their card key: resolve the card on the \
                                DHT, open a WireGuard tunnel to a published endpoint, and settle \
                                <sats> satoshis on Bitcoin L1. Enforces the same spend policy and \
                                signed ledger as cm_send. Returns the txid and a block-explorer URL.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "card_key": { "type": "string" },
                        "sats": { "type": "integer", "minimum": 1 }
                    },
                    "required": ["card_key", "sats"]
                }
            },
            {
                "name": "cm_balance",
                "description": "Report the wallet's on-chain balance (confirmed and pending \
                                satoshis) on the active network.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
                }
            },
            {
                "name": "cm_confs",
                "description": "Report a payment's confirmation count and status label \
                                (pending/soft/final/failed) for <txid>, and reconcile the ledger \
                                so its recorded status advances.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "txid": { "type": "string" }
                    },
                    "required": ["txid"]
                }
            },
            {
                "name": "cm_collections",
                "description": "List every issued receive index and its collection state \
                                (index, address, status awaiting|paid, txid, sats) as JSON — the \
                                seller's agent polls this to know when a payment has arrived.",
                "inputSchema": {
                    "type": "object",
                    "properties": {}
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
            | Some("cm_balance")
            | Some("cm_confs")
            | Some("cm_collections")
    ) {
        return match name {
            Some(other) => error_frame(id, -32602, &format!("unknown tool: {other}")),
            None => error_frame(id, -32602, "missing tool name"),
        };
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
        Some("cm_confs") => call_confs(w, id, args),
        Some("cm_collections") => call_collections(w, id),
        _ => call_balance(w, id),
    }
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
    let txid = crate::pay::send(&mut led, &ext, &int, to, sats, policy.max_fee_sats)?;
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
    Ok(format!(
        "network: {}\nconfirmed: {} sats\npending: {} sats",
        storage::network_label(),
        b.confirmed,
        b.pending
    ))
}

/// cm_pay: validate arguments (protocol-level on failure), then run the DHT pay
/// recipe (tool-level on failure — no card / no endpoint / policy reject / chain
/// unreachable). The wallet is already unlocked by `tools_call`.
fn call_pay(wallet: &wallet::Wallet, id: Value, args: Option<&Value>) -> Value {
    let Some(args) = args else {
        return error_frame(id, -32602, "cm_pay requires arguments { card_key, sats }");
    };
    let Some(card_key) = args.get("card_key").and_then(Value::as_str) else {
        return error_frame(id, -32602, "cm_pay: 'card_key' must be a string");
    };
    let Some(sats) = args.get("sats").and_then(Value::as_u64) else {
        return error_frame(id, -32602, "cm_pay: 'sats' must be a positive integer");
    };
    if sats == 0 {
        return error_frame(id, -32602, "cm_pay: 'sats' must be >= 1");
    }
    match pay_card(wallet, card_key, sats) {
        Ok(text) => tool_ok(id, &text),
        Err(e) => tool_err(id, &e.to_string()),
    }
}

/// The `cm pay <card-key> <sats>` recipe (main.rs DHT arm) on the held wallet:
/// parse the card key, resolve the peer's card on the DHT, then open a
/// WireGuard tunnel to each published endpoint in turn and settle via
/// `tunnel::pay`. The spend policy (amount cap + OFAC address blocklist) is NOT
/// re-checked here on purpose: it already runs inside the pay path
/// (`net::run_payer`, invoked by `tunnel::pay`), so duplicating it would be
/// redundant and a second copy to keep in sync. `tunnel::pay` returns `()`, so
/// the settled txid is read back from the ledger's most recent Sent entry to
/// build the returned txid + explorer URL.
fn pay_card(wallet: &wallet::Wallet, card_key: &str, sats: u64) -> Result<String, Box<dyn Error>> {
    let key = discover::parse_card_key(card_key)?;
    eprintln!("cm mcp: cm_pay resolving card {}… (DHT)", &card_key.trim()[..8]);
    let card = discover::resolve(&key)?.ok_or("no card on the DHT for that key")?;
    if card.ep.is_empty() {
        return Err("peer published no endpoint (not accepting inbound sessions)".into());
    }
    // Try each published endpoint (v4, v6, …) in order until one session
    // succeeds; if all fail, surface the last error.
    let ledger_path = storage::ledger_path(wallet)?;
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

/// cm_collections: per-index receive state (index, address, awaiting|paid,
/// txid, sats) as a JSON array — the seller's agent polls this to know when a
/// payment has arrived and it can deliver.
fn call_collections(wallet: &wallet::Wallet, id: Value) -> Value {
    match collections_report(wallet) {
        Ok(text) => tool_ok(id, &text),
        Err(e) => tool_err(id, &e.to_string()),
    }
}

fn collections_report(wallet: &wallet::Wallet) -> Result<String, Box<dyn Error>> {
    let led = ledger::Ledger::open_with_identity(
        storage::ledger_path(wallet)?,
        wallet.signing_keypair()?,
    )?;
    let mut rows = Vec::new();
    for c in led.collections() {
        // A row is "paid" once a Received binds a txid to the index, else it is
        // still "awaiting" the on-chain deposit.
        let status = if c.txid.is_some() { "paid" } else { "awaiting" };
        let mut row = json!({
            "index": c.index,
            "address": wallet.address(c.index)?.to_string(),
            "status": status,
            "sats": c.sats,
        });
        if let Some(txid) = c.txid {
            row["txid"] = json!(txid);
        }
        rows.push(row);
    }
    Ok(serde_json::to_string_pretty(&Value::Array(rows))?)
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
        // card_key not a string.
        let args = json!({ "sats": 1000 });
        assert_eq!(err_code(&call_pay(&w, json!(1), Some(&args))), Some(-32602));
        // sats missing / not a positive integer.
        let args = json!({ "card_key": "ab" });
        assert_eq!(err_code(&call_pay(&w, json!(1), Some(&args))), Some(-32602));
        // sats == 0 is rejected before any resolve.
        let args = json!({ "card_key": "ab", "sats": 0 });
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
