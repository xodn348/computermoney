//! ledger — append-only signed log. The source of truth.
//!
//! Every economic fact is one JSON line, fsync'd on write. Balance, the
//! next receive index, and the set of in-flight payments are all *folds*
//! over this file — there is no separate database to drift out of sync.
//!
//! Why this is load-bearing (steps 7-8 of the architecture notes): the
//! daemon is a stateless worker. It can die at any point and a restart
//! recovers everything by reading this file and re-checking the chain.
//! `pending` entries are literally the work queue.
//!
//! Each line is a signed envelope: `{ "entry": <Entry>, "sig": <hex> }`.
//! The signature is a BIP-340 Schnorr signature, by the wallet's identity
//! key, over the SHA-256 of the entry's canonical JSON bytes. A ledger
//! opened with that identity (`open_with_identity`) verifies every line on
//! load and refuses to start if any entry was altered or forged. The
//! append/fold/reconcile shape is unchanged — signing wraps the entry, it
//! does not touch the economic fields the folds read.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

/// Confirmation stage. Maps to the locked thresholds: 0 confs = Pending,
/// 1 conf = Soft (receipt ack), 3 confs = Final (delivery gate). `Failed` is
/// off that ladder entirely: it is never inferred from a confirmation count,
/// only set explicitly by reconcile when a Sent tx is proven dead (its inputs
/// are gone). A Failed send never moved money, so it is not debited.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Pending,
    Soft,
    Final,
    Failed,
}

impl Status {
    /// Map a confirmation count to a status using the locked thresholds.
    /// Never returns `Failed`: that is a deliberate reconcile decision, not a
    /// function of the confirmation count.
    pub fn from_confirmations(confs: u32) -> Status {
        match confs {
            0 => Status::Pending,
            1 | 2 => Status::Soft,
            _ => Status::Final,
        }
    }
}

/// One economic fact. `seq` is monotonic. The signature lives in the
/// `Record` envelope around this entry, not on the entry itself, so the
/// signed bytes are exactly the entry's economic content.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Entry {
    /// A receive address was handed to a counterparty.
    AddressIssued { seq: u64, index: u32 },
    /// We broadcast a payment. `at` is the unix time of the send, so a
    /// rolling spend window (the daily limit) is a fold over the ledger.
    Sent { seq: u64, txid: String, sats: u64, to: String, status: Status, at: u64 },
    /// A payment to one of our addresses was observed.
    Received { seq: u64, txid: String, sats: u64, index: u32, status: Status },
    /// reconcile() advanced a payment's confirmation status. Append-only:
    /// the original Sent/Received entry stays; the effective status is
    /// the latest update for that txid.
    StatusUpdate { seq: u64, txid: String, status: Status },
    /// A Silent Payments output paying us was found by scanning the chain.
    /// Keyed by the outpoint `(txid, vout)` — an SP payment has no issued
    /// receive index; it lands on a one-time address only we can detect.
    /// `tweak` is the hex ECDH tweak `t_k`, persisted so the spend key
    /// `d = b_spend + t_k` is recoverable from seed + ledger alone. Shares
    /// the pending/soft/final ladder with `Received`: reconcile advances it
    /// via `StatusUpdate` because it is txid-keyed like every other payment.
    SpReceived { seq: u64, txid: String, vout: u32, sats: u64, tweak: String, status: Status },
    /// An SP outpoint we hold was spent. Append-only and set-semantic: the
    /// spender books this when it builds the spend, and the scanner books it
    /// again when it later observes the spend on-chain — duplicates for the
    /// same outpoint are harmless, the folds treat SpSpent as a set.
    SpSpent { seq: u64, txid: String, vout: u32 },
}

/// One issued receive index and its collection state: awaiting payment
/// (`txid: None`) or paid (the observed tx, its sats). Live confirmation
/// counts are the chain's to answer (`cm_confs`), not the ledger's.
///
/// `sp` distinguishes a Silent Payments receipt from a descriptor row. When
/// `sp` is true, this receipt has no issued receive address: `index` holds the
/// output's `vout`, not a receive index, so a renderer must NOT feed it to
/// `wallet.address(index)` — show `txid:vout` instead.
pub struct Collection {
    pub index: u32,
    pub txid: Option<String>,
    pub sats: u64,
    pub sp: bool,
}

/// An unspent Silent Payments output we can spend. `tweak` is the hex ECDH
/// tweak `t_k`; the spend key is `d = b_spend + t_k` (mod n). Only final
/// (fully confirmed) unspent outputs are returned, so `sum(sats)` equals
/// `sp_balance()`.
pub struct SpUtxo {
    pub txid: String,
    pub vout: u32,
    pub sats: u64,
    pub tweak: String,
}

/// Wall-clock unix seconds. Used to stamp Sent entries; 0 if the clock is
/// somehow before the epoch (it isn't).
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Entry {
    fn seq(&self) -> u64 {
        match self {
            Entry::AddressIssued { seq, .. }
            | Entry::Sent { seq, .. }
            | Entry::Received { seq, .. }
            | Entry::StatusUpdate { seq, .. }
            | Entry::SpReceived { seq, .. }
            | Entry::SpSpent { seq, .. } => *seq,
        }
    }
}

/// On-disk line format: the entry plus its detached signature. The sig is
/// empty for an unsigned ledger (no identity).
#[derive(Serialize, Deserialize)]
struct Record {
    entry: Entry,
    #[serde(default)]
    sig: String,
}

pub struct Ledger {
    path: PathBuf,
    entries: Vec<Entry>,
    identity: Option<Keypair>,
}

impl Ledger {
    /// Open (or start) an unsigned ledger: entries are written with an
    /// empty signature and not verified on load. Used by tests and any
    /// caller without a key.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        Self::open_inner(path, None)
    }

    /// Open (or start) a ledger bound to `identity`: every appended entry is
    /// Schnorr-signed by that key, and every line is verified against it on
    /// load. A tampered or foreign-signed line makes this return an error
    /// instead of trusting the file.
    pub fn open_with_identity(path: impl AsRef<Path>, identity: Keypair) -> std::io::Result<Self> {
        Self::open_inner(path, Some(identity))
    }

    fn open_inner(path: impl AsRef<Path>, identity: Option<Keypair>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        // Create the ledger's parent directory up front, so the first append
        // (`cm receive` / `cm pay` / `cm send`) doesn't fail with ENOENT when
        // CM_LEDGER points at a directory that does not exist yet.
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let verify_key = identity.map(|kp| kp.x_only_public_key().0);
        let mut entries = Vec::new();
        if path.exists() {
            let file = OpenOptions::new().read(true).open(&path)?;
            for line in BufReader::new(file).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let rec: Record = serde_json::from_str(&line)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                if let Some(pk) = &verify_key {
                    if !verify(pk, &rec.entry, &rec.sig) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("ledger signature check failed at seq {}", rec.entry.seq()),
                        ));
                    }
                }
                entries.push(rec.entry);
            }
        }
        Ok(Self { path, entries, identity })
    }

    /// Append one entry: sign it (if this ledger has an identity), serialize
    /// the envelope to a line, write, fsync. The fsync is the durability
    /// guarantee — an entry that returns Ok is on disk.
    pub fn append(&mut self, entry: Entry) -> std::io::Result<()> {
        let sig = match &self.identity {
            Some(kp) => sign(kp, &entry),
            None => String::new(),
        };
        let rec = Record { entry, sig };
        let mut line = serde_json::to_string(&rec)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        line.push('\n');
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        file.write_all(line.as_bytes())?;
        file.sync_all()?;
        self.entries.push(rec.entry);
        Ok(())
    }

    /// Next sequence number to use.
    pub fn next_seq(&self) -> u64 {
        self.entries.last().map(|e| e.seq() + 1).unwrap_or(0)
    }

    /// Next receive index = highest issued index + 1. This is the fold
    /// that replaces the in-memory counter, so addresses never repeat
    /// across restarts.
    pub fn next_address_index(&self) -> u32 {
        self.entries
            .iter()
            .filter_map(|e| match e {
                Entry::AddressIssued { index, .. } => Some(*index + 1),
                _ => None,
            })
            .max()
            .unwrap_or(0)
    }

    /// Issued receive indexes with no matching Received yet — addresses handed
    /// out but not paid. The seller daemon scans exactly these on-chain.
    pub fn issued_unpaid(&self) -> Vec<u32> {
        let paid: std::collections::HashSet<u32> = self
            .entries
            .iter()
            .filter_map(|e| match e {
                Entry::Received { index, .. } => Some(*index),
                _ => None,
            })
            .collect();
        self.entries
            .iter()
            .filter_map(|e| match e {
                Entry::AddressIssued { index, .. } if !paid.contains(index) => Some(*index),
                _ => None,
            })
            .collect()
    }

    /// Whether any Sent or Received already references `txid`. The daemon calls
    /// this before recording a chain-detected deposit so a Notify and a poll
    /// cannot double-record the same payment.
    pub fn has_txid(&self, txid: &str) -> bool {
        self.entries.iter().any(|e| {
            matches!(e,
                Entry::Sent { txid: t, .. }
                | Entry::Received { txid: t, .. }
                | Entry::SpReceived { txid: t, .. } if t == txid)
        })
    }

    /// Whether a specific SP outpoint `(txid, vout)` is already booked. The
    /// scanner calls this to skip outputs it has recorded on a previous pass —
    /// SP receipts are outpoint-keyed, so `has_txid` (txid-only) is too coarse.
    pub fn has_sp_output(&self, txid: &str, vout: u32) -> bool {
        self.entries.iter().any(|e| {
            matches!(e, Entry::SpReceived { txid: t, vout: v, .. } if t == txid && *v == vout)
        })
    }

    /// One row per issued receive index: `txid: None` while awaiting payment, or
    /// ledger stores a status, not a live count; a caller that needs the count
    /// refreshes via `chain`.
    pub fn collections(&self) -> Vec<Collection> {
        let mut rows: Vec<Collection> = self
            .entries
            .iter()
            .filter_map(|e| match e {
                Entry::AddressIssued { index, .. } => {
                    let recv = self.entries.iter().find_map(|r| match r {
                        Entry::Received { txid, sats, index: ri, .. } if ri == index => {
                            Some((txid.clone(), *sats))
                        }
                        _ => None,
                    });
                    Some(match recv {
                        Some((txid, sats)) => {
                            Collection { index: *index, txid: Some(txid), sats, sp: false }
                        }
                        None => Collection { index: *index, txid: None, sats: 0, sp: false },
                    })
                }
                _ => None,
            })
            .collect();
        // SP receipts have no issued index; each is its own row keyed by vout.
        for e in &self.entries {
            if let Entry::SpReceived { txid, vout, sats, .. } = e {
                rows.push(Collection { index: *vout, txid: Some(txid.clone()), sats: *sats, sp: true });
            }
        }
        rows
    }

    /// Record a chain-detected deposit as a Pending Received — but only if this
    /// txid is not already in the ledger (a Notify may have logged it first).
    /// Returns whether a new entry was appended. Mirrors exactly the path
    /// `net::run_receiver` uses (next_seq + append of a Pending Received); this
    /// is the no-listener path where the daemon polls `chain::deposits_to` and
    /// logs what it finds without double-counting a payment the wire reported.
    pub fn record_received(&mut self, txid: &str, sats: u64, index: u32) -> std::io::Result<bool> {
        if self.has_txid(txid) {
            return Ok(false);
        }
        let seq = self.next_seq();
        self.append(Entry::Received {
            seq,
            txid: txid.to_string(),
            sats,
            index,
            status: Status::Pending,
        })?;
        Ok(true)
    }

    /// Record a scanned Silent Payments output as a Pending SpReceived — but
    /// only if this outpoint is not already booked. `tweak` is the hex ECDH
    /// tweak. Returns whether a new entry was appended. Mirrors
    /// `record_received`: dedup, then a Pending entry the reconcile loop
    /// advances to Final. The scanner calls this for every fresh match.
    pub fn record_sp_received(
        &mut self,
        txid: &str,
        vout: u32,
        sats: u64,
        tweak: &str,
    ) -> std::io::Result<bool> {
        if self.has_sp_output(txid, vout) {
            return Ok(false);
        }
        let seq = self.next_seq();
        self.append(Entry::SpReceived {
            seq,
            txid: txid.to_string(),
            vout,
            sats,
            tweak: tweak.to_string(),
            status: Status::Pending,
        })?;
        Ok(true)
    }

    /// Mark an SP outpoint spent. Idempotent: a second call for the same
    /// outpoint is a no-op (returns false) so repeated scans and the spender's
    /// own booking do not grow the log. The fold is set-semantic regardless,
    /// so a duplicate that does slip through (e.g. a race) is still harmless.
    pub fn record_sp_spent(&mut self, txid: &str, vout: u32) -> std::io::Result<bool> {
        if self.is_sp_spent(txid, vout) {
            return Ok(false);
        }
        let seq = self.next_seq();
        self.append(Entry::SpSpent { seq, txid: txid.to_string(), vout })?;
        Ok(true)
    }

    /// The set of SP outpoints marked spent.
    fn sp_spent_set(&self) -> std::collections::HashSet<(String, u32)> {
        self.entries
            .iter()
            .filter_map(|e| match e {
                Entry::SpSpent { txid, vout, .. } => Some((txid.clone(), *vout)),
                _ => None,
            })
            .collect()
    }

    fn is_sp_spent(&self, txid: &str, vout: u32) -> bool {
        self.entries.iter().any(|e| {
            matches!(e, Entry::SpSpent { txid: t, vout: v, .. } if t == txid && *v == vout)
        })
    }

    /// Spendable Silent Payments balance: final SpReceived outputs whose
    /// outpoint has not been spent. Kept separate from `balance()` (which is
    /// the descriptor/Received fold) — `cm_balance` sums the two, so SP funds
    /// are never double-counted against on-chain descriptor state.
    pub fn sp_balance(&self) -> u64 {
        let spent = self.sp_spent_set();
        self.entries
            .iter()
            .filter_map(|e| match e {
                Entry::SpReceived { txid, vout, sats, .. }
                    if self.latest_status(txid) == Some(Status::Final)
                        && !spent.contains(&(txid.clone(), *vout)) =>
                {
                    Some(*sats)
                }
                _ => None,
            })
            .sum()
    }

    /// Silent-payment income that has been scanned and booked but is not yet
    /// final (0–2 confirmations), and therefore not yet spendable. Reported as
    /// an informational line by `cm_balance` so a fresh payment is visible the
    /// instant it is scanned, before it crosses the 3-confirmation threshold
    /// that moves it into `sp_balance()`. Spent outputs are excluded.
    pub fn sp_incoming(&self) -> u64 {
        let spent = self.sp_spent_set();
        self.entries
            .iter()
            .filter_map(|e| match e {
                Entry::SpReceived { txid, vout, sats, .. }
                    if self.latest_status(txid) != Some(Status::Final)
                        && !spent.contains(&(txid.clone(), *vout)) =>
                {
                    Some(*sats)
                }
                _ => None,
            })
            .sum()
    }

    /// Unspent, fully-confirmed SP outputs with their tweaks — the spend
    /// candidates. `sum(sats)` equals `sp_balance()`. The spender pins these as
    /// foreign UTXOs and key-path-signs each with `d = b_spend + tweak`.
    pub fn sp_utxos(&self) -> Vec<SpUtxo> {
        let spent = self.sp_spent_set();
        self.entries
            .iter()
            .filter_map(|e| match e {
                Entry::SpReceived { txid, vout, sats, tweak, .. }
                    if self.latest_status(txid) == Some(Status::Final)
                        && !spent.contains(&(txid.clone(), *vout)) =>
                {
                    Some(SpUtxo {
                        txid: txid.clone(),
                        vout: *vout,
                        sats: *sats,
                        tweak: tweak.clone(),
                    })
                }
                _ => None,
            })
            .collect()
    }

    /// Effective (latest) status for a txid, folding in any StatusUpdate.
    pub fn latest_status(&self, txid: &str) -> Option<Status> {
        let mut s = None;
        for e in &self.entries {
            match e {
                Entry::Sent { txid: t, status, .. }
                | Entry::Received { txid: t, status, .. }
                | Entry::SpReceived { txid: t, status, .. }
                | Entry::StatusUpdate { txid: t, status, .. }
                    if t == txid =>
                {
                    s = Some(*status)
                }
                _ => {}
            }
        }
        s
    }

    /// Spendable balance = final received minus everything sent, using
    /// each txid's effective status. Pending receives are excluded; sends
    /// are debited immediately (the money has left).
    pub fn balance(&self) -> u64 {
        let mut bal: i64 = 0;
        for e in &self.entries {
            match e {
                Entry::Received { txid, sats, .. } => {
                    if self.latest_status(txid) == Some(Status::Final) {
                        bal += *sats as i64;
                    }
                }
                Entry::Sent { txid, sats, .. } => {
                    // A Failed send never left the wallet — do not debit it.
                    if self.latest_status(txid) != Some(Status::Failed) {
                        bal -= *sats as i64;
                    }
                }
                _ => {}
            }
        }
        bal.max(0) as u64
    }

    /// The work queue: each in-flight payment's txid (effective status not
    /// yet Final). A restarted daemon re-checks exactly these. Deduped so
    /// a txid with several StatusUpdates appears once.
    pub fn pending(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for e in &self.entries {
            let txid = match e {
                Entry::Sent { txid, .. }
                | Entry::Received { txid, .. }
                | Entry::SpReceived { txid, .. } => txid,
                _ => continue,
            };
            // Final and Failed are both terminal — off the work queue.
            let status = self.latest_status(txid);
            if seen.insert(txid.clone())
                && status != Some(Status::Final)
                && status != Some(Status::Failed)
            {
                out.push(txid.clone());
            }
        }
        out
    }

    /// Total satoshis sent at or after `cutoff` (unix seconds). The fold
    /// behind the policy daily limit — a send counts the moment it is
    /// broadcast, regardless of how it later confirms.
    pub fn spent_since(&self, cutoff: u64) -> u64 {
        self.entries
            .iter()
            .filter_map(|e| match e {
                Entry::Sent { sats, at, .. } if *at >= cutoff => Some(*sats),
                _ => None,
            })
            .sum()
    }

    /// Record a confirmation-status change (append-only).
    pub fn update_status(&mut self, txid: &str, status: Status) -> std::io::Result<()> {
        let seq = self.next_seq();
        self.append(Entry::StatusUpdate { seq, txid: txid.to_string(), status })
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Directory holding not-yet-settled signed transactions: `pending/`
    /// beside the ledger file. Each `<txid>.tx` is the raw consensus hex of a
    /// broadcast-pending payment, written BEFORE the broadcast so reconcile
    /// can recover (rebroadcast) a tx a crash left in limbo (Finding C).
    pub fn sidecar_dir(&self) -> PathBuf {
        match self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            Some(dir) => dir.join("pending"),
            None => PathBuf::from("pending"),
        }
    }

    fn sidecar_path(&self, txid: &str) -> PathBuf {
        self.sidecar_dir().join(format!("{txid}.tx"))
    }

    /// Persist a signed tx's raw hex as `pending/<txid>.tx`, fsync'd. The
    /// fsync mirrors `append`: a sidecar that returns Ok is durably on disk
    /// before the broadcast that follows it.
    pub fn write_sidecar(&self, txid: &str, tx_hex: &str) -> std::io::Result<()> {
        let dir = self.sidecar_dir();
        std::fs::create_dir_all(&dir)?;
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(dir.join(format!("{txid}.tx")))?;
        file.write_all(tx_hex.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    /// Read back a sidecar's hex, or `None` if there is no sidecar for `txid`.
    pub fn read_sidecar(&self, txid: &str) -> std::io::Result<Option<String>> {
        match std::fs::read_to_string(self.sidecar_path(txid)) {
            Ok(s) => Ok(Some(s)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Remove a sidecar once its payment has settled (Soft/Final) or been
    /// declared Failed. Absent is success — reconcile may call this more than
    /// once for the same txid.
    pub fn remove_sidecar(&self, txid: &str) -> std::io::Result<()> {
        match std::fs::remove_file(self.sidecar_path(txid)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// The txids that currently have a sidecar (not-yet-settled signed txs).
    pub fn list_sidecars(&self) -> std::io::Result<Vec<String>> {
        let mut out = Vec::new();
        let rd = match std::fs::read_dir(self.sidecar_dir()) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for entry in rd {
            let name = entry?.file_name();
            if let Some(txid) = name.to_string_lossy().strip_suffix(".tx") {
                out.push(txid.to_string());
            }
        }
        Ok(out)
    }
}

/// The 32-byte message a signature commits to: SHA-256 of the entry's
/// canonical JSON. serde_json emits struct fields in declaration order, so
/// the same entry always produces the same bytes — signer and verifier
/// agree without a separate canonicalization step.
fn digest(entry: &Entry) -> Message {
    let bytes = serde_json::to_vec(entry).expect("Entry always serializes");
    let hash = sha256::Hash::hash(&bytes);
    Message::from_digest(hash.to_byte_array())
}

/// Schnorr-sign an entry, returning the signature as hex.
fn sign(keypair: &Keypair, entry: &Entry) -> String {
    let secp = Secp256k1::new();
    secp.sign_schnorr_no_aux_rand(&digest(entry), keypair).to_string()
}

/// Verify a hex Schnorr signature over an entry. Any parse or check
/// failure is a rejection, never a panic.
fn verify(pubkey: &XOnlyPublicKey, entry: &Entry, sig_hex: &str) -> bool {
    let Ok(sig) = Signature::from_str(sig_hex) else {
        return false;
    };
    Secp256k1::new()
        .verify_schnorr(&sig, &digest(entry), pubkey)
        .is_ok()
}

/// reconcile — the function steps 5/7/8 all fold into. For every pending
/// payment, ask the chain for its confirmation count and advance the
/// ledger status if it changed. ledger/ never touches the network itself
/// (that stays in chain/); reconcile is the composition point.
pub fn reconcile(ledger: &mut Ledger) -> Result<usize, Box<dyn std::error::Error>> {
    let mut changed = 0;
    for txid in ledger.pending() {
        let confs = crate::chain::confirmations(&txid)?;
        if confs == 0 {
            // Write-ahead recovery. A still-unconfirmed Sent may have crashed
            // between the durable ledger write and its broadcast, or been
            // broadcast and later evicted. If we still hold its signed tx,
            // rebroadcast it. A hard rejection (inputs gone / conflicting
            // spend) proves it can never confirm — mark it Failed, which
            // un-debits it, and drop the sidecar. Anything else (accepted,
            // already-known, transient, or no sidecar) stays Pending: only a
            // provably-dead tx becomes Failed.
            if let Some(hex) = ledger.read_sidecar(&txid)? {
                if let crate::chain::Rebroadcast::Rejected(reason) =
                    crate::chain::rebroadcast_hex(&hex)?
                {
                    eprintln!("[reconcile] {txid} can never confirm ({reason}); marking failed");
                    ledger.update_status(&txid, Status::Failed)?;
                    ledger.remove_sidecar(&txid)?;
                    changed += 1;
                    continue;
                }
            }
        }
        let new_status = Status::from_confirmations(confs);
        if ledger.latest_status(&txid) != Some(new_status) {
            ledger.update_status(&txid, new_status)?;
            changed += 1;
        }
        // Once a payment is settling (Soft/Final), its sidecar is no longer
        // needed for recovery.
        if confs >= 1 {
            ledger.remove_sidecar(&txid)?;
        }
    }

    // Orphan sidecars: pay::send writes the sidecar before appending the Sent
    // entry, so a crash in that gap leaves a signed tx on disk that was never
    // recorded and never broadcast — the money never moved. With no ledger
    // entry it can never confirm and must not be rebroadcast blind, so drop it.
    let recorded: std::collections::HashSet<&str> = ledger
        .entries()
        .iter()
        .filter_map(|e| match e {
            Entry::Sent { txid, .. } => Some(txid.as_str()),
            _ => None,
        })
        .collect();
    let orphans: Vec<String> = ledger
        .list_sidecars()?
        .into_iter()
        .filter(|txid| !recorded.contains(txid.as_str()))
        .collect();
    for txid in orphans {
        ledger.remove_sidecar(&txid)?;
    }

    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("cm_ledger_test_{name}_{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn append_then_reopen_recovers_entries() {
        let path = temp_path("reopen");
        {
            let mut l = Ledger::open(&path).unwrap();
            l.append(Entry::AddressIssued { seq: 0, index: 0 }).unwrap();
            l.append(Entry::Received {
                seq: 1,
                txid: "aa".into(),
                sats: 50_000,
                index: 0,
                status: Status::Pending,
            })
            .unwrap();
        }
        // Reopen from disk — a fresh daemon recovering state.
        let l2 = Ledger::open(&path).unwrap();
        assert_eq!(l2.entries().len(), 2);
        assert_eq!(l2.next_seq(), 2);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn next_address_index_survives_restart() {
        let path = temp_path("index");
        {
            let mut l = Ledger::open(&path).unwrap();
            l.append(Entry::AddressIssued { seq: 0, index: 0 }).unwrap();
            l.append(Entry::AddressIssued { seq: 1, index: 1 }).unwrap();
        }
        let l2 = Ledger::open(&path).unwrap();
        assert_eq!(l2.next_address_index(), 2, "index must not repeat after restart");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn balance_counts_only_final_receives_minus_sends() {
        let path = temp_path("balance");
        let mut l = Ledger::open(&path).unwrap();
        l.append(Entry::Received { seq: 0, txid: "a".into(), sats: 100_000, index: 0, status: Status::Final }).unwrap();
        l.append(Entry::Received { seq: 1, txid: "b".into(), sats: 50_000, index: 1, status: Status::Pending }).unwrap();
        l.append(Entry::Sent { seq: 2, txid: "c".into(), sats: 30_000, to: "x".into(), status: Status::Soft, at: 0 }).unwrap();
        // 100k final received - 30k sent; the 50k pending receive doesn't count.
        assert_eq!(l.balance(), 70_000);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn pending_is_the_work_queue() {
        let path = temp_path("pending");
        let mut l = Ledger::open(&path).unwrap();
        l.append(Entry::AddressIssued { seq: 0, index: 0 }).unwrap();
        l.append(Entry::Received { seq: 1, txid: "a".into(), sats: 1, index: 0, status: Status::Final }).unwrap();
        l.append(Entry::Sent { seq: 2, txid: "b".into(), sats: 1, to: "x".into(), status: Status::Pending, at: 0 }).unwrap();
        l.append(Entry::Received { seq: 3, txid: "c".into(), sats: 1, index: 1, status: Status::Soft }).unwrap();
        // Only the non-final Sent and the Soft Received are in flight.
        assert_eq!(l.pending().len(), 2);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn status_update_overrides_original_and_unblocks_balance() {
        let path = temp_path("statusupdate");
        let mut l = Ledger::open(&path).unwrap();
        // A receive lands pending — not yet spendable.
        l.append(Entry::Received { seq: 0, txid: "tx1".into(), sats: 50_000, index: 0, status: Status::Pending }).unwrap();
        assert_eq!(l.balance(), 0);
        assert_eq!(l.pending(), vec!["tx1".to_string()]);

        // reconcile sees 1 conf, then 3 confs.
        l.update_status("tx1", Status::Soft).unwrap();
        assert_eq!(l.balance(), 0, "soft is not yet final");
        l.update_status("tx1", Status::Final).unwrap();

        // Now final: spendable, and off the work queue.
        assert_eq!(l.latest_status("tx1"), Some(Status::Final));
        assert_eq!(l.balance(), 50_000);
        assert!(l.pending().is_empty());

        // And it all survives a restart (append-only StatusUpdates on disk).
        let l2 = Ledger::open(&path).unwrap();
        assert_eq!(l2.balance(), 50_000);
        assert!(l2.pending().is_empty());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn spent_since_sums_sends_in_window() {
        let path = temp_path("spent");
        let mut l = Ledger::open(&path).unwrap();
        l.append(Entry::Sent { seq: 0, txid: "old".into(), sats: 10_000, to: "x".into(), status: Status::Final, at: 1_000 }).unwrap();
        l.append(Entry::Sent { seq: 1, txid: "new".into(), sats: 25_000, to: "y".into(), status: Status::Pending, at: 2_000 }).unwrap();
        // Cutoff between the two sends counts only the newer one.
        assert_eq!(l.spent_since(1_500), 25_000);
        assert_eq!(l.spent_since(0), 35_000);
        assert_eq!(l.spent_since(3_000), 0);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn status_thresholds() {
        assert_eq!(Status::from_confirmations(0), Status::Pending);
        assert_eq!(Status::from_confirmations(1), Status::Soft);
        assert_eq!(Status::from_confirmations(2), Status::Soft);
        assert_eq!(Status::from_confirmations(3), Status::Final);
        assert_eq!(Status::from_confirmations(6), Status::Final);
    }

    #[test]
    fn failed_send_is_refunded_and_leaves_the_queue() {
        let path = temp_path("failed");
        let mut l = Ledger::open(&path).unwrap();
        l.append(Entry::Received { seq: 0, txid: "r".into(), sats: 100_000, index: 0, status: Status::Final }).unwrap();
        l.append(Entry::Sent { seq: 1, txid: "s".into(), sats: 30_000, to: "x".into(), status: Status::Pending, at: 0 }).unwrap();
        // While Pending, the send is debited and on the work queue.
        assert_eq!(l.balance(), 70_000);
        assert!(l.pending().contains(&"s".to_string()));

        // reconcile proves it dead and marks it Failed: the money never left,
        // so balance is restored and it drops off the queue.
        l.update_status("s", Status::Failed).unwrap();
        assert_eq!(l.balance(), 100_000, "a Failed send must not be debited");
        assert!(!l.pending().contains(&"s".to_string()), "Failed is terminal");

        // Survives a restart.
        let l2 = Ledger::open(&path).unwrap();
        assert_eq!(l2.balance(), 100_000);
        assert!(l2.pending().is_empty());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn sidecar_write_read_remove_roundtrip() {
        // Own directory so the shared `pending/` dir can't collide with other
        // tests, and list_sidecars() sees only this ledger's sidecars.
        let mut dir = std::env::temp_dir();
        dir.push(format!("cm_sidecar_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let l = Ledger::open(dir.join("ledger.jsonl")).unwrap();

        let txid = "deadbeef";
        assert_eq!(l.read_sidecar(txid).unwrap(), None, "absent before write");
        l.write_sidecar(txid, "0100abcd").unwrap();
        assert_eq!(l.read_sidecar(txid).unwrap(), Some("0100abcd".to_string()));
        assert!(l.list_sidecars().unwrap().contains(&txid.to_string()));

        l.remove_sidecar(txid).unwrap();
        assert_eq!(l.read_sidecar(txid).unwrap(), None, "gone after remove");
        assert!(!l.list_sidecars().unwrap().contains(&txid.to_string()));
        // Removing an absent sidecar is a no-op success.
        l.remove_sidecar(txid).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reconcile_drops_orphan_sidecars() {
        // A sidecar with no matching Sent entry (crash between write_sidecar
        // and the ledger append) is garbage: reconcile removes it. No pending
        // entries means reconcile makes no network call.
        let mut dir = std::env::temp_dir();
        dir.push(format!("cm_orphan_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut l = Ledger::open(dir.join("ledger.jsonl")).unwrap();

        l.write_sidecar("orphantxid", "0100abcd").unwrap();
        assert!(l.pending().is_empty(), "no entries -> nothing pending -> no chain call");
        reconcile(&mut l).unwrap();
        assert_eq!(l.read_sidecar("orphantxid").unwrap(), None, "orphan sidecar dropped");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn collections_track_issued_and_paid_indexes() {
        let path = temp_path("collections");
        let mut l = Ledger::open(&path).unwrap();
        l.append(Entry::AddressIssued { seq: 0, index: 0 }).unwrap();
        l.append(Entry::AddressIssued { seq: 1, index: 1 }).unwrap();

        // A deposit lands on index 0 only; the same txid is not double-recorded.
        assert!(l.record_received("tx0", 40_000, 0).unwrap(), "first record appends");
        assert!(!l.record_received("tx0", 40_000, 0).unwrap(), "duplicate txid is a no-op");

        assert!(l.has_txid("tx0"));
        assert!(!l.has_txid("nope"));
        assert_eq!(l.issued_unpaid(), vec![1], "index 1 is still awaiting payment");

        let cols = l.collections();
        assert_eq!(cols.len(), 2);
        let c0 = cols.iter().find(|c| c.index == 0).unwrap();
        assert_eq!(c0.txid.as_deref(), Some("tx0"));
        assert_eq!(c0.sats, 40_000);
        let c1 = cols.iter().find(|c| c.index == 1).unwrap();
        assert_eq!(c1.txid, None);
        assert_eq!(c1.sats, 0);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn signed_entries_verify_and_tamper_is_detected() {
        use crate::wallet::Wallet;
        let (w, _) = Wallet::generate().unwrap();
        let kp = w.signing_keypair().unwrap();
        let path = temp_path("signed");
        {
            let mut l = Ledger::open_with_identity(&path, kp).unwrap();
            l.append(Entry::AddressIssued { seq: 0, index: 0 }).unwrap();
            l.append(Entry::Received {
                seq: 1,
                txid: "aa".into(),
                sats: 50_000,
                index: 0,
                status: Status::Pending,
            })
            .unwrap();
        }
        // Same identity reopens and verifies every line.
        let l2 = Ledger::open_with_identity(&path, kp).unwrap();
        assert_eq!(l2.entries().len(), 2);

        // Alter a signed amount on disk; the signature no longer matches.
        let tampered = std::fs::read_to_string(&path).unwrap().replace("50000", "99999");
        std::fs::write(&path, tampered).unwrap();
        assert!(
            Ledger::open_with_identity(&path, kp).is_err(),
            "a tampered amount must fail the signature check"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn foreign_identity_cannot_verify_our_ledger() {
        use crate::wallet::Wallet;
        let (a, _) = Wallet::generate().unwrap();
        let (b, _) = Wallet::generate().unwrap();
        let path = temp_path("foreign");
        {
            let mut l = Ledger::open_with_identity(&path, a.signing_keypair().unwrap()).unwrap();
            l.append(Entry::AddressIssued { seq: 0, index: 0 }).unwrap();
        }
        // B's key must reject A's signatures.
        assert!(
            Ledger::open_with_identity(&path, b.signing_keypair().unwrap()).is_err(),
            "another agent's key must not verify our ledger"
        );
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn sp_entries_roundtrip_on_disk() {
        let path = temp_path("sp_roundtrip");
        let tw = "ab".repeat(32); // 64-hex = 32 bytes, the tweak's real width
        {
            let mut l = Ledger::open(&path).unwrap();
            l.append(Entry::SpReceived {
                seq: 0,
                txid: "sp0".into(),
                vout: 1,
                sats: 5_000,
                tweak: tw.clone(),
                status: Status::Pending,
            })
            .unwrap();
            l.append(Entry::SpSpent { seq: 1, txid: "sp0".into(), vout: 1 }).unwrap();
        }
        // A fresh daemon recovers both variants byte-for-byte.
        let l2 = Ledger::open(&path).unwrap();
        assert_eq!(l2.entries().len(), 2);
        assert_eq!(l2.next_seq(), 2);
        match &l2.entries()[0] {
            Entry::SpReceived { txid, vout, sats, tweak, status, .. } => {
                assert_eq!((txid.as_str(), *vout, *sats), ("sp0", 1, 5_000));
                assert_eq!(tweak, &tw);
                assert_eq!(*status, Status::Pending);
            }
            other => panic!("expected SpReceived, got {other:?}"),
        }
        assert!(matches!(l2.entries()[1], Entry::SpSpent { vout: 1, .. }));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn sp_balance_counts_final_unspent_only() {
        let path = temp_path("sp_balance");
        let tw = "cd".repeat(32);
        let mut l = Ledger::open(&path).unwrap();
        // final + unspent -> counts
        l.record_sp_received("a", 0, 10_000, &tw).unwrap();
        l.update_status("a", Status::Final).unwrap();
        // final but spent -> excluded
        l.record_sp_received("b", 0, 7_000, &tw).unwrap();
        l.update_status("b", Status::Final).unwrap();
        l.record_sp_spent("b", 0).unwrap();
        // pending -> excluded from balance, but on the work queue
        l.record_sp_received("c", 0, 3_000, &tw).unwrap();

        assert_eq!(l.sp_balance(), 10_000);
        // sp_utxos is exactly the spendable set: sum == sp_balance, tweak carried.
        let utxos = l.sp_utxos();
        assert_eq!(utxos.len(), 1);
        assert_eq!(utxos[0].txid, "a");
        assert_eq!(utxos[0].sats, 10_000);
        assert_eq!(utxos[0].tweak, tw);
        assert_eq!(utxos.iter().map(|u| u.sats).sum::<u64>(), l.sp_balance());
        assert!(l.pending().contains(&"c".to_string()), "pending SP income is on the queue");

        // The whole SP view survives a restart.
        let l2 = Ledger::open(&path).unwrap();
        assert_eq!(l2.sp_balance(), 10_000);
        assert_eq!(l2.sp_utxos().len(), 1);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn duplicate_spspent_is_harmless_and_deduped() {
        let path = temp_path("sp_dup");
        let tw = "ef".repeat(32);
        let mut l = Ledger::open(&path).unwrap();
        l.record_sp_received("x", 2, 8_000, &tw).unwrap();
        l.update_status("x", Status::Final).unwrap();
        assert_eq!(l.sp_balance(), 8_000);

        // record_sp_spent is idempotent: the spender books it, the scanner's
        // later observation is a no-op.
        assert!(l.record_sp_spent("x", 2).unwrap(), "first mark appends");
        assert!(!l.record_sp_spent("x", 2).unwrap(), "second mark is a no-op");

        // Even a raw duplicate that bypasses the dedup (a true race) is harmless:
        // the fold is set-semantic, so the balance is 0, never negative.
        let seq = l.next_seq();
        l.append(Entry::SpSpent { seq, txid: "x".into(), vout: 2 }).unwrap();
        assert_eq!(l.sp_balance(), 0);
        assert!(l.sp_utxos().is_empty());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn sp_received_follows_the_status_ladder() {
        let path = temp_path("sp_ladder");
        let tw = "12".repeat(32);
        let mut l = Ledger::open(&path).unwrap();
        assert!(l.record_sp_received("t", 0, 6_000, &tw).unwrap());
        // Outpoint dedup: the same (txid, vout) is refused on a re-scan.
        assert!(!l.record_sp_received("t", 0, 6_000, &tw).unwrap());

        // Pending: not spendable, but on the reconcile work queue.
        assert_eq!(l.sp_balance(), 0);
        assert_eq!(l.pending(), vec!["t".to_string()]);

        // reconcile advances SP income through the same update_status mechanism.
        l.update_status("t", Status::Soft).unwrap();
        assert_eq!(l.sp_balance(), 0, "soft is not final");
        l.update_status("t", Status::Final).unwrap();
        assert_eq!(l.sp_balance(), 6_000);
        assert!(l.pending().is_empty(), "final leaves the queue");

        assert!(l.has_txid("t"));
        assert!(l.has_sp_output("t", 0));
        assert!(!l.has_sp_output("t", 1), "a different vout is a different outpoint");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn collections_include_sp_rows() {
        let path = temp_path("sp_collections");
        let tw = "34".repeat(32);
        let mut l = Ledger::open(&path).unwrap();
        l.append(Entry::AddressIssued { seq: 0, index: 0 }).unwrap();
        l.record_sp_received("spx", 3, 9_000, &tw).unwrap();

        let cols = l.collections();
        let sp_rows: Vec<_> = cols.iter().filter(|c| c.sp).collect();
        assert_eq!(sp_rows.len(), 1);
        assert_eq!(sp_rows[0].index, 3, "an SP row carries the vout in `index`");
        assert_eq!(sp_rows[0].txid.as_deref(), Some("spx"));
        assert_eq!(sp_rows[0].sats, 9_000);

        let desc_rows: Vec<_> = cols.iter().filter(|c| !c.sp).collect();
        assert_eq!(desc_rows.len(), 1);
        assert_eq!(desc_rows[0].index, 0);
        assert!(!desc_rows[0].sp);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn signed_sp_entries_verify_on_reopen() {
        use crate::wallet::Wallet;
        let (w, _) = Wallet::generate().unwrap();
        let kp = w.signing_keypair().unwrap();
        let path = temp_path("sp_signed");
        let tw = "56".repeat(32);
        {
            let mut l = Ledger::open_with_identity(&path, kp).unwrap();
            l.record_sp_received("s", 0, 4_000, &tw).unwrap();
            l.update_status("s", Status::Final).unwrap();
            l.record_sp_spent("s", 0).unwrap();
        }
        // Signing wraps SP entries like any other; every line re-verifies.
        let l2 = Ledger::open_with_identity(&path, kp).unwrap();
        assert_eq!(l2.entries().len(), 3);
        assert_eq!(l2.sp_balance(), 0, "final then spent nets to zero");
        std::fs::remove_file(&path).unwrap();
    }
}
