//! demo — the whole milestone 1 flow end to end, in one process.
//!
//! Two identities (payer with coins, fresh payee) agree a payment using
//! the protocol verbs and settle it on the real chain, each keeping its
//! own signed ledger. The two `[A->B]` / `[B->A]` hops are where the
//! WireGuard tunnel goes; here they are in-process calls so the demo is
//! self-contained. Swapping a real tunnel underneath changes nothing
//! above this line — that is the whole point of the coordination/
//! settlement split.

use crate::chain;
use crate::ledger::{self, Entry, Ledger, Status};
use crate::protocol::{Message, Receiver};
use crate::wallet::Wallet;

fn temp_ledger(tag: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("cm_demo_{tag}_{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

pub fn run(amount: u64) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== computermoney milestone 1 — end-to-end payment ===\n");

    // Payer: the wallet that holds coins (encrypted seed or CM_MNEMONIC).
    let payer = crate::storage::load_wallet()?;
    let (p_ext, p_int) = payer.descriptors();
    let mut payer_ledger = Ledger::open_with_identity(temp_ledger("payer"), payer.signing_keypair()?)?;

    // Payee: a fresh identity. In a real run this is the other terminal.
    let (payee, payee_phrase) = Wallet::generate()?;
    let mut payee_ledger = Ledger::open_with_identity(temp_ledger("payee"), payee.signing_keypair()?)?;
    let mut rx = Receiver::new(&payee, payee_ledger.next_address_index());
    println!("payee identity (fresh): {}…", &payee_phrase[..24]);

    // 1. Payer asks the payee for an address.  [A -> B over tunnel]
    println!("\n[A->B] addr_request {{ sats: {amount} }}");
    let reply = rx
        .handle(Message::AddrRequest { sats: amount })?
        .ok_or("payee gave no address")?;
    let (addr, index) = match reply {
        Message::AddrResponse { address, index } => (address, index),
        other => return Err(format!("unexpected reply: {other:?}").into()),
    };
    payee_ledger.append(Entry::AddressIssued { seq: payee_ledger.next_seq(), index })?;
    println!("[B->A] addr_response {{ index: {index}, address: {addr} }}");

    // 2. Payer settles on-chain (real broadcast). [Bitcoin L1]
    println!("\n[A] building + signing + broadcasting {amount} sats…");
    let txid = chain::send(&p_ext, &p_int, &addr, amount, None)?;
    payer_ledger.append(Entry::Sent {
        seq: payer_ledger.next_seq(),
        txid: txid.to_string(),
        sats: amount,
        to: addr.clone(),
        status: Status::Pending,
        at: ledger::now_unix(),
    })?;
    println!("[A] txid {txid}");

    // 3. Payer notifies (fast-path hint; the chain is the real proof).
    //    [A -> B over tunnel]
    println!("\n[A->B] notify {{ txid: {txid} }}");
    payee_ledger.append(Entry::Received {
        seq: payee_ledger.next_seq(),
        txid: txid.to_string(),
        sats: amount,
        index,
        status: Status::Pending,
    })?;

    // 4. Payee reconciles against the chain — independent of the notify.
    println!("\n[B] reconciling against mutinynet…");
    let changed = ledger::reconcile(&mut payee_ledger)?;
    let confs = chain::confirmations(&txid.to_string())?;
    println!("[B] {confs} confirmations, {changed} status update(s)");
    println!("[B] spendable balance: {} sats (final-only)", payee_ledger.balance());
    println!("[B] work queue (pending txids): {:?}", payee_ledger.pending());

    println!(
        "\nsettlement is live. watch it reach final (3 conf, ~90s on mutinynet):\n  \
         cm confs {txid}\n  \
         https://mutinynet.com/tx/{txid}"
    );
    Ok(())
}
