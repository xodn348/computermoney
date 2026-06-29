//! mcp — an in-process MCP server so an AI agent pays Bitcoin in plain language.
//!
//! `cm mcp` speaks JSON-RPC 2.0 over stdio (the MCP transport): one compact
//! JSON object per line in, one per line out, with every byte of diagnostics
//! routed to stderr so stdout stays a clean protocol stream. Two tools are
//! exposed — `cm_send` (broadcast a payment) and `cm_balance` (on-chain
//! balance) — each reusing the exact CLI recipes so the agent path and the
//! human path move money identically. The wallet is unlocked ONCE at startup
//! and held for the process lifetime; the passphrase is never a tool argument.
//!
//! Hand-rolled on serde_json alone (no rmcp/tokio): the esplora client is
//! blocking, so a synchronous read → dispatch → write loop is the whole server.

use std::error::Error;
use std::io::{BufRead, Write};

use serde_json::{json, Value};

use crate::{chain, ledger, policy, storage, wallet};

/// MCP protocol version this server implements. We echo back the client's
/// requested version on `initialize` (forward-compatible); this is the
/// fallback advertised when the client omits one.
const PROTOCOL_VERSION: &str = "2025-06-18";

/// Run the stdio MCP server until stdin closes. The wallet is unlocked exactly
/// once here (via `CM_PASSPHRASE`/`CM_MNEMONIC`) and reused for every call.
pub fn run() -> Result<(), Box<dyn Error>> {
    let wallet = storage::load_wallet()?;
    eprintln!(
        "cm mcp: wallet unlocked on {}; serving cm_send + cm_balance over stdio",
        storage::network_label()
    );

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
        let frame = dispatch(&wallet, id, &msg);
        write_frame(&mut writer, &frame)?;
    }
    Ok(())
}

/// Route an id-bearing request to its handler and return the frame to emit.
fn dispatch(wallet: &wallet::Wallet, id: Value, msg: &Value) -> Value {
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
                "name": "cm_balance",
                "description": "Report the wallet's on-chain balance (confirmed and pending \
                                satoshis) on the active network.",
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
fn tools_call(wallet: &wallet::Wallet, id: Value, params: Option<&Value>) -> Value {
    let name = params.and_then(|p| p.get("name")).and_then(Value::as_str);
    let args = params.and_then(|p| p.get("arguments"));
    match name {
        Some("cm_send") => call_send(wallet, id, args),
        Some("cm_balance") => call_balance(wallet, id),
        Some(other) => error_frame(id, -32602, &format!("unknown tool: {other}")),
        None => error_frame(id, -32602, "missing tool name"),
    }
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
/// signed ledger, gate on policy (amount + blocklist), broadcast through the
/// money chokepoint (which also runs the mainnet guard), then record the Sent
/// entry. Returns the human text the agent reads back.
fn send_payment(wallet: &wallet::Wallet, to: &str, sats: u64) -> Result<String, Box<dyn Error>> {
    let mut led =
        ledger::Ledger::open_with_identity(storage::ledger_path(), wallet.signing_keypair()?)?;
    let policy = policy::Policy::load()?;
    let spent = led.spent_since(ledger::now_unix().saturating_sub(policy::DAILY_WINDOW_SECS));
    policy.check_amount(sats, spent)?;
    policy.check_address(to)?;
    let (ext, int) = wallet.descriptors();
    eprintln!("cm mcp: cm_send {sats} sats -> {to}: syncing + building + broadcasting…");
    let txid = chain::send(&ext, &int, to, sats, policy.max_fee_sats)?;
    led.append(ledger::Entry::Sent {
        seq: led.next_seq(),
        txid: txid.to_string(),
        sats,
        to: to.to_string(),
        status: ledger::Status::Pending,
        at: ledger::now_unix(),
    })?;
    Ok(format!(
        "txid: {txid}\n{}",
        storage::explorer_tx_url(&txid.to_string())
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
