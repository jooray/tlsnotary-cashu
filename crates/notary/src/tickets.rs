//! Tickets: what a payment buys. Stored in SQLite; only the SHA-256 of a
//! ticket is ever written down.

use std::{path::Path, sync::Mutex};

use anyhow::Result;
use base64::Engine;
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use tlsnc_protocol::Egress;

pub const PREFIX: &str = "tk_";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub hash: String,
    pub tier: String,
    pub egress: Egress,
    pub expires_at: u64,
    pub attempts_left: u32,
    pub spent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TicketError {
    #[error("unknown ticket")]
    Unknown,
    #[error("ticket expired")]
    Expired,
    #[error("ticket already used")]
    Spent,
    #[error("no attempts left on this ticket")]
    NoAttempts,
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn hash(ticket: &str) -> String {
    hex::encode(Sha256::digest(ticket.as_bytes()))
}

/// A new random ticket string.
pub fn generate() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("{PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

pub struct Store {
    db: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Connection::open(path)?;
        Self::init(db)
    }

    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(db: Connection) -> Result<Self> {
        db.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS tickets (
                 hash TEXT PRIMARY KEY,
                 tier TEXT NOT NULL,
                 egress TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 expires_at INTEGER NOT NULL,
                 attempts_left INTEGER NOT NULL,
                 spent_at INTEGER,
                 mint TEXT NOT NULL,
                 amount INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS sessions (
                 id INTEGER PRIMARY KEY,
                 ticket_hash TEXT NOT NULL,
                 started_at INTEGER NOT NULL,
                 ended_at INTEGER,
                 mode TEXT,
                 outcome TEXT
             );",
        )?;
        Ok(Self { db: Mutex::new(db) })
    }

    /// Records a paid ticket and returns the ticket string to hand out.
    pub fn issue(&self, tier: &str, egress: Egress, ttl: u64, attempts: u32, mint: &str, amount: u64) -> Result<(String, u64)> {
        let ticket = generate();
        let created = now();
        let expires = created + ttl;
        self.db.lock().unwrap().execute(
            "INSERT INTO tickets (hash, tier, egress, created_at, expires_at, attempts_left, mint, amount)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![hash(&ticket), tier, egress.as_str(), created, expires, attempts, mint, amount],
        )?;
        Ok((ticket, expires))
    }

    pub fn get(&self, ticket: &str) -> Result<Ticket, TicketError> {
        let h = hash(ticket);
        let row = self
            .db
            .lock()
            .unwrap()
            .query_row(
                "SELECT tier, egress, expires_at, attempts_left, spent_at FROM tickets WHERE hash = ?1",
                params![h],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, u64>(2)?,
                        r.get::<_, u32>(3)?,
                        r.get::<_, Option<u64>>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| TicketError::Unknown)?
            .ok_or(TicketError::Unknown)?;
        let (tier, egress, expires_at, attempts_left, spent_at) = row;
        Ok(Ticket {
            hash: h,
            tier,
            egress: egress.parse().map_err(|_| TicketError::Unknown)?,
            expires_at,
            attempts_left,
            spent: spent_at.is_some(),
        })
    }

    /// A ticket that may start a session now.
    pub fn usable(&self, ticket: &str) -> Result<Ticket, TicketError> {
        let t = self.get(ticket)?;
        if t.spent {
            return Err(TicketError::Spent);
        }
        if t.expires_at < now() {
            return Err(TicketError::Expired);
        }
        if t.attempts_left == 0 {
            return Err(TicketError::NoAttempts);
        }
        Ok(t)
    }

    /// Consumes one attempt and records the session start. Atomic: two
    /// concurrent sessions cannot both take the last attempt.
    pub fn start_attempt(&self, hash: &str) -> Result<i64, TicketError> {
        let db = self.db.lock().unwrap();
        let changed = db
            .execute(
                "UPDATE tickets SET attempts_left = attempts_left - 1
                 WHERE hash = ?1 AND attempts_left > 0 AND spent_at IS NULL AND expires_at >= ?2",
                params![hash, now()],
            )
            .map_err(|_| TicketError::Unknown)?;
        if changed == 0 {
            return Err(TicketError::NoAttempts);
        }
        db.execute(
            "INSERT INTO sessions (ticket_hash, started_at) VALUES (?1, ?2)",
            params![hash, now()],
        )
        .map_err(|_| TicketError::Unknown)?;
        Ok(db.last_insert_rowid())
    }

    /// Gives an attempt back (the session never really started, e.g. the
    /// WebSocket upgrade failed).
    pub fn refund_attempt(&self, hash: &str) {
        let _ = self.db.lock().unwrap().execute(
            "UPDATE tickets SET attempts_left = attempts_left + 1 WHERE hash = ?1 AND spent_at IS NULL",
            params![hash],
        );
    }

    pub fn finish(&self, session_id: i64, hash: &str, mode: &str, outcome: Result<(), &str>) {
        let db = self.db.lock().unwrap();
        let outcome_text = match outcome {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("error: {e}"),
        };
        let _ = db.execute(
            "UPDATE sessions SET ended_at = ?1, mode = ?2, outcome = ?3 WHERE id = ?4",
            params![now(), mode, outcome_text, session_id],
        );
        if outcome.is_ok() {
            let _ = db.execute(
                "UPDATE tickets SET spent_at = ?1 WHERE hash = ?2",
                params![now(), hash],
            );
        }
    }

    /// (tickets, spent tickets, received amount) for `tlsnc-notary stats`.
    pub fn stats(&self) -> Result<(u64, u64, u64)> {
        Ok(self.db.lock().unwrap().query_row(
            "SELECT COUNT(*), COUNT(spent_at), COALESCE(SUM(amount), 0) FROM tickets",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_lifecycle() {
        let s = Store::in_memory().unwrap();
        let (t, _) = s.issue("S", Egress::Client, 60, 2, "https://mint", 42).unwrap();
        assert!(t.starts_with(PREFIX));
        let tk = s.usable(&t).unwrap();
        assert_eq!(tk.attempts_left, 2);
        assert_eq!(tk.egress, Egress::Client);

        let s1 = s.start_attempt(&tk.hash).unwrap();
        s.finish(s1, &tk.hash, "mpc", Err("boom"));
        assert_eq!(s.usable(&t).unwrap().attempts_left, 1);

        let s2 = s.start_attempt(&tk.hash).unwrap();
        assert_eq!(s.start_attempt(&tk.hash), Err(TicketError::NoAttempts));
        s.finish(s2, &tk.hash, "mpc", Ok(()));
        assert_eq!(s.usable(&t), Err(TicketError::Spent));
        assert_eq!(s.usable("tk_nope"), Err(TicketError::Unknown));
    }

    #[test]
    fn expired_ticket() {
        let s = Store::in_memory().unwrap();
        let (t, _) = s.issue("S", Egress::Notary, 0, 1, "https://mint", 42).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert_eq!(s.usable(&t), Err(TicketError::Expired));
    }
}
