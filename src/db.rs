//! Storage and the listing rules. Everything here runs inside one SQLite connection; callers
//! hold the lock for the whole operation.

use crate::{net, DAY};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use std::collections::{HashMap, HashSet};
use std::path::Path;

pub type Result<T> = rusqlite::Result<T>;

/// A report counts for 14 days.
pub const WINDOW: i64 = 14 * DAY;
/// Distinct registration networks needed for a listing.
pub const MIN_NETWORKS: usize = 3;
/// Removed entries stay in the incremental list this long; older cursors get the full list.
pub const REMOVED_KEEP: i64 = 30 * DAY;

pub const KINDS: [&str; 4] = ["digest", "domain", "ip", "from"];

/// Allowlist seeded on first start: brands, carriers and freemail domains that phishing and
/// spam name or send from, but that must never be listed as `domain` or `from`.
/// Documented in README.md; the admin can remove entries.
pub const SEED_ALLOWLIST: &[&str] = &[
    // freemail
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "icloud.com",
    "me.com",
    "aol.com",
    "gmx.de",
    "gmx.net",
    "web.de",
    "t-online.de",
    "freenet.de",
    "posteo.de",
    "mailbox.org",
    "proton.me",
    "protonmail.com",
    // big brands
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "amazon.de",
    "paypal.com",
    "ebay.com",
    "ebay.de",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "youtube.com",
    // carriers
    "dhl.de",
    "dhl.com",
    "deutschepost.de",
    "dpd.de",
    "dpd.com",
    "hermesworld.com",
    "myhermes.de",
    "gls-group.eu",
    "ups.com",
    "fedex.com",
];

pub fn open(path: &Path) -> Result<Connection> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    migrate(&conn)?;
    Ok(conn)
}

pub fn open_in_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    migrate(&conn)?;
    Ok(conn)
}

/// Schema steps by `user_version`. Add new steps; never rewrite old ones.
fn migrate(conn: &Connection) -> Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if version < 1 {
        conn.execute_batch(
            "BEGIN;
            CREATE TABLE servers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                software TEXT NOT NULL,
                contact TEXT,
                key_hash TEXT NOT NULL UNIQUE,
                reg_net TEXT NOT NULL,
                created INTEGER NOT NULL,
                banned INTEGER NOT NULL DEFAULT 0,
                day INTEGER NOT NULL DEFAULT 0,
                day_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE reports (
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                server_id TEXT NOT NULL REFERENCES servers(id),
                spam_user INTEGER NOT NULL DEFAULT 0,
                spam_filter INTEGER NOT NULL DEFAULT 0,
                ham_user INTEGER NOT NULL DEFAULT 0,
                ham_filter INTEGER NOT NULL DEFAULT 0,
                last_spam INTEGER NOT NULL DEFAULT 0,
                last_ham INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (kind, value, server_id)
            ) WITHOUT ROWID;
            CREATE INDEX reports_server ON reports(server_id);
            CREATE TABLE listed (
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                score REAL NOT NULL,
                expires INTEGER NOT NULL,
                seq INTEGER NOT NULL,
                removed INTEGER NOT NULL DEFAULT 0,
                changed INTEGER NOT NULL,
                PRIMARY KEY (kind, value)
            ) WITHOUT ROWID;
            CREATE INDEX listed_seq ON listed(seq);
            CREATE INDEX listed_expires ON listed(removed, expires);
            CREATE TABLE allowlist (
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (kind, value)
            );
            CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
            INSERT INTO meta VALUES ('seq', 0), ('purged', 0);
            PRAGMA user_version = 1;
            COMMIT;",
        )?;
        for kind in ["domain", "from"] {
            for value in SEED_ALLOWLIST {
                conn.execute(
                    "INSERT INTO allowlist (kind, value, note) VALUES (?1, ?2, 'seed')",
                    params![kind, value],
                )?;
            }
        }
    }
    Ok(())
}

fn meta(tx: &Connection, key: &str) -> Result<i64> {
    tx.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
}

fn next_seq(tx: &Connection) -> Result<i64> {
    tx.query_row(
        "UPDATE meta SET value = value + 1 WHERE key = 'seq' RETURNING value",
        [],
        |r| r.get(0),
    )
}

// --- servers -------------------------------------------------------------------------------

pub struct NewServer<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub software: &'a str,
    pub contact: Option<&'a str>,
    pub key_hash: &'a str,
    pub reg_net: &'a str,
}

pub fn insert_server(conn: &Connection, s: &NewServer, now: i64) -> Result<()> {
    conn.execute(
        "INSERT INTO servers (id, name, software, contact, key_hash, reg_net, created)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![s.id, s.name, s.software, s.contact, s.key_hash, s.reg_net, now],
    )?;
    Ok(())
}

/// `(server id, banned)` for a key hash.
pub fn server_by_key(conn: &Connection, key_hash: &str) -> Result<Option<(String, bool)>> {
    conn.query_row(
        "SELECT id, banned FROM servers WHERE key_hash = ?1",
        [key_hash],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .optional()
}

pub struct ServerRow {
    pub id: String,
    pub name: String,
    pub software: String,
    pub contact: Option<String>,
    pub reg_net: String,
    pub created: i64,
    pub banned: bool,
}

pub fn servers(conn: &Connection) -> Result<Vec<ServerRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, software, contact, reg_net, created, banned FROM servers ORDER BY created",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok(ServerRow {
            id: r.get(0)?,
            name: r.get(1)?,
            software: r.get(2)?,
            contact: r.get(3)?,
            reg_net: r.get(4)?,
            created: r.get(5)?,
            banned: r.get(6)?,
        })
    })?;
    rows.collect()
}

/// Bans or unbans a server and recomputes everything it reported. `false` if there is no such
/// server.
pub fn set_banned(conn: &mut Connection, id: &str, banned: bool, now: i64) -> Result<bool> {
    let tx = conn.transaction()?;
    if tx.execute(
        "UPDATE servers SET banned = ?2 WHERE id = ?1",
        params![id, banned],
    )? == 0
    {
        return Ok(false);
    }
    let items: Vec<(String, String)> = {
        let mut stmt = tx.prepare("SELECT kind, value FROM reports WHERE server_id = ?1")?;
        let rows = stmt.query_map([id], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<Result<_>>()?
    };
    for (kind, value) in items {
        recompute(&tx, &kind, &value, now)?;
    }
    tx.commit()?;
    Ok(true)
}

// --- reports -------------------------------------------------------------------------------

/// One stored report: what a server saw, already validated and normalized.
pub struct Report {
    pub spam: bool,
    pub user: bool,
    /// `(kind, value)` pairs, without duplicates.
    pub items: Vec<(&'static str, String)>,
}

pub enum Accept {
    Accepted(usize),
    /// The server's daily budget would be exceeded.
    RateLimited,
}

/// Stores a batch of reports from one server and recomputes what they touched.
pub fn add_reports(
    conn: &mut Connection,
    server: &str,
    reports: &[Report],
    per_day: u32,
    now: i64,
) -> Result<Accept> {
    let tx = conn.transaction()?;
    let today = now.div_euclid(DAY);
    let (day, count): (i64, i64) = tx.query_row(
        "SELECT day, day_count FROM servers WHERE id = ?1",
        [server],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let count = if day == today { count } else { 0 };
    let n = reports.len() as i64;
    if count + n > i64::from(per_day) {
        return Ok(Accept::RateLimited);
    }
    tx.execute(
        "UPDATE servers SET day = ?2, day_count = ?3 WHERE id = ?1",
        params![server, today, count + n],
    )?;
    let window = now - WINDOW;
    let mut touched = HashSet::new();
    for report in reports {
        for (kind, value) in &report.items {
            let row: Option<[i64; 6]> = tx
                .query_row(
                    "SELECT spam_user, spam_filter, ham_user, ham_filter, last_spam, last_ham
                     FROM reports WHERE kind = ?1 AND value = ?2 AND server_id = ?3",
                    params![kind, value, server],
                    |r| {
                        Ok([
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                        ])
                    },
                )
                .optional()?;
            let [mut su, mut sf, mut hu, mut hf, mut ls, mut lh] = row.unwrap_or_default();
            // Counters only cover the window: an old count starts again from zero.
            if report.spam {
                if ls <= window {
                    (su, sf) = (0, 0);
                }
                if report.user {
                    su += 1
                } else {
                    sf += 1
                }
                ls = now;
            } else {
                if lh <= window {
                    (hu, hf) = (0, 0);
                }
                if report.user {
                    hu += 1
                } else {
                    hf += 1
                }
                lh = now;
            }
            tx.execute(
                "INSERT OR REPLACE INTO reports
                 (kind, value, server_id, spam_user, spam_filter, ham_user, ham_filter, last_spam, last_ham)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![kind, value, server, su, sf, hu, hf, ls, lh],
            )?;
            touched.insert((*kind, value.clone()));
        }
    }
    for (kind, value) in touched {
        recompute(&tx, kind, &value, now)?;
    }
    tx.commit()?;
    Ok(Accept::Accepted(reports.len()))
}

// --- listing rules -------------------------------------------------------------------------

/// What an entry should look like now: `Some((score, expires))` when listed.
pub fn evaluate(tx: &Connection, kind: &str, value: &str, now: i64) -> Result<Option<(f64, i64)>> {
    if allowlisted(tx, kind, value)? {
        return Ok(None);
    }
    let window = now - WINDOW;
    let mut stmt = tx.prepare_cached(
        "SELECT s.reg_net, r.spam_user, r.spam_filter, r.ham_user, r.ham_filter, r.last_spam, r.last_ham
         FROM reports r JOIN servers s ON s.id = r.server_id
         WHERE r.kind = ?1 AND r.value = ?2 AND s.banned = 0",
    )?;
    let rows = stmt.query_map(params![kind, value], |r| {
        Ok((
            r.get::<_, String>(0)?,
            [
                r.get::<_, i64>(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ],
        ))
    })?;
    // Votes count servers, not reports: one server cannot outvote others by repeating itself.
    let (mut spam, mut ham) = (0i64, 0i64);
    // Per registration network: newest spam report, and whether a person reported it.
    let mut networks: HashMap<String, (i64, bool)> = HashMap::new();
    for row in rows {
        let (net, [su, sf, hu, hf, ls, lh]) = row?;
        if ls > window && su + sf > 0 {
            spam += if su > 0 { 2 } else { 1 };
            let entry = networks.entry(net).or_insert((0, false));
            entry.0 = entry.0.max(ls);
            entry.1 |= su > 0;
        }
        if lh > window && hu + hf > 0 {
            ham += if hu > 0 { 2 } else { 1 };
        }
    }
    if networks.len() < MIN_NETWORKS || spam < 3 * ham {
        return Ok(None);
    }
    let mut newest: Vec<i64> = networks.values().map(|n| n.0).collect();
    newest.sort_unstable_by(|a, b| b.cmp(a));
    // Listed while three networks reported within the window; every ham vote takes a day off.
    let expires = newest[MIN_NETWORKS - 1] + WINDOW - ham.min(10) * DAY;
    if expires <= now {
        return Ok(None);
    }
    let weight: i64 = networks.values().map(|n| if n.1 { 2 } else { 1 }).sum();
    let score = 1.0 + 3.0 * (weight.min(10) - 3) as f64 / 7.0;
    Ok(Some(((score * 100.0).round() / 100.0, expires)))
}

/// Brings the listed row of one entry in line with the reports, bumping its sequence number
/// whenever a client has to learn about the change.
pub fn recompute(tx: &Connection, kind: &str, value: &str, now: i64) -> Result<()> {
    let want = evaluate(tx, kind, value, now)?;
    let have: Option<(f64, i64, bool)> = tx
        .query_row(
            "SELECT score, expires, removed FROM listed WHERE kind = ?1 AND value = ?2",
            params![kind, value],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    match (want, have) {
        (None, Some((_, _, false))) => {
            let seq = next_seq(tx)?;
            tx.execute(
                "UPDATE listed SET removed = 1, seq = ?3, changed = ?4 WHERE kind = ?1 AND value = ?2",
                params![kind, value, seq, now],
            )?;
        }
        (None, _) => {}
        // Same score and the expiry only moved later by less than a day: nothing to tell.
        // The sweep looks again when the stored expiry comes.
        (Some((score, expires)), Some((old_score, old_expires, false)))
            if score == old_score && expires >= old_expires && expires - old_expires < DAY => {}
        (Some((score, expires)), _) => {
            let seq = next_seq(tx)?;
            tx.execute(
                "INSERT OR REPLACE INTO listed (kind, value, score, expires, seq, removed, changed)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
                params![kind, value, score, expires, seq, now],
            )?;
        }
    }
    Ok(())
}

/// Expires what is due, forgets reports outside the window and old removals.
pub fn sweep(conn: &mut Connection, now: i64) -> Result<()> {
    let tx = conn.transaction()?;
    let due: Vec<(String, String)> = {
        let mut stmt =
            tx.prepare("SELECT kind, value FROM listed WHERE removed = 0 AND expires <= ?1")?;
        let rows = stmt.query_map([now], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<Result<_>>()?
    };
    for (kind, value) in due {
        recompute(&tx, &kind, &value, now)?;
    }
    tx.execute(
        "DELETE FROM reports WHERE max(last_spam, last_ham) <= ?1",
        [now - WINDOW],
    )?;
    let purged: Option<i64> = tx.query_row(
        "SELECT max(seq) FROM listed WHERE removed = 1 AND changed <= ?1",
        [now - REMOVED_KEEP],
        |r| r.get(0),
    )?;
    if let Some(purged) = purged {
        tx.execute(
            "DELETE FROM listed WHERE removed = 1 AND seq <= ?1",
            [purged],
        )?;
        tx.execute(
            "UPDATE meta SET value = max(value, ?1) WHERE key = 'purged'",
            [purged],
        )?;
    }
    tx.commit()
}

pub struct Entry {
    pub kind: String,
    pub value: String,
    pub score: f64,
    pub expires: i64,
}

pub struct List {
    pub cursor: i64,
    pub full: bool,
    pub entries: Vec<Entry>,
    pub removed: Vec<(String, String)>,
}

/// The full list, or the changes after `since` when that cursor is still served.
pub fn list(conn: &Connection, since: Option<i64>) -> Result<List> {
    let cursor = meta(conn, "seq")?;
    let purged = meta(conn, "purged")?;
    let since = since.filter(|s| *s >= purged && *s <= cursor);
    let mut out = List {
        cursor,
        full: since.is_none(),
        entries: Vec::new(),
        removed: Vec::new(),
    };
    let mut stmt = conn.prepare(
        "SELECT kind, value, score, expires, removed FROM listed
         WHERE seq > ?1 AND (?2 OR removed = 0) ORDER BY seq",
    )?;
    let rows = stmt.query_map(params![since.unwrap_or(0), since.is_some()], |r| {
        Ok((
            Entry {
                kind: r.get(0)?,
                value: r.get(1)?,
                score: r.get(2)?,
                expires: r.get(3)?,
            },
            r.get::<_, bool>(4)?,
        ))
    })?;
    for row in rows {
        let (entry, removed) = row?;
        if removed {
            out.removed.push((entry.kind, entry.value));
        } else {
            out.entries.push(entry);
        }
    }
    Ok(out)
}

// --- allowlist -----------------------------------------------------------------------------

fn allowlisted(tx: &Connection, kind: &str, value: &str) -> Result<bool> {
    let exact = |v: &str| -> Result<bool> {
        tx.prepare_cached("SELECT 1 FROM allowlist WHERE kind = ?1 AND value = ?2")?
            .exists(params![kind, v])
    };
    if exact(value)? {
        return Ok(true);
    }
    match kind {
        // A listed domain's parents: allowing example.com also covers mail.example.com.
        "domain" | "from" => {
            let mut rest = value;
            while let Some((_, parent)) = rest.split_once('.') {
                if parent.contains('.') && exact(parent)? {
                    return Ok(true);
                }
                rest = parent;
            }
            Ok(false)
        }
        "ip" => {
            let mut stmt = tx.prepare_cached(
                "SELECT value FROM allowlist WHERE kind = 'ip' AND value LIKE '%/%'",
            )?;
            let nets = stmt.query_map([], |r| r.get::<_, String>(0))?;
            for net in nets {
                if net::parse_cidr(&net?).is_some_and(|n| net::cidr_contains(n, value)) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

/// Normalizes an allowlist value for its kind; `None` if it is not valid for it.
pub fn allowlist_value(kind: &str, value: &str) -> Option<String> {
    match kind {
        "domain" | "from" => net::domain(value),
        "digest" => crate::digest::is_valid(value).then(|| value.to_string()),
        "ip" if value.contains('/') => net::parse_cidr(value).map(|(ip, p)| format!("{ip}/{p}")),
        "ip" => {
            let ip: std::net::IpAddr = value.parse().ok()?;
            Some(net::reported_ip(value).unwrap_or_else(|| ip.to_string()))
        }
        _ => None,
    }
}

fn recompute_kind(tx: &Transaction, kind: &str, now: i64) -> Result<()> {
    let items: Vec<String> = {
        let mut stmt = tx.prepare(
            "SELECT value FROM listed WHERE kind = ?1 AND removed = 0
             UNION SELECT DISTINCT value FROM reports WHERE kind = ?1",
        )?;
        let rows = stmt.query_map([kind], |r| r.get(0))?;
        rows.collect::<Result<_>>()?
    };
    for value in items {
        recompute(tx, kind, &value, now)?;
    }
    Ok(())
}

pub fn allowlist_add(
    conn: &mut Connection,
    kind: &str,
    value: &str,
    note: &str,
    now: i64,
) -> Result<()> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT OR REPLACE INTO allowlist (kind, value, note) VALUES (?1, ?2, ?3)",
        params![kind, value, note],
    )?;
    recompute_kind(&tx, kind, now)?;
    tx.commit()
}

pub fn allowlist_remove(conn: &mut Connection, kind: &str, value: &str, now: i64) -> Result<bool> {
    let tx = conn.transaction()?;
    let removed = tx.execute(
        "DELETE FROM allowlist WHERE kind = ?1 AND value = ?2",
        params![kind, value],
    )? > 0;
    recompute_kind(&tx, kind, now)?;
    tx.commit()?;
    Ok(removed)
}

pub fn allowlist(conn: &Connection) -> Result<Vec<(String, String, String)>> {
    let mut stmt = conn.prepare("SELECT kind, value, note FROM allowlist ORDER BY kind, value")?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    rows.collect()
}

// --- stats ---------------------------------------------------------------------------------

/// Named counts for `uwuspamnet stats`.
pub fn stats(conn: &Connection) -> Result<Vec<(String, i64)>> {
    let one = |sql: &str| conn.query_row(sql, [], |r| r.get::<_, i64>(0));
    let mut out = vec![
        ("servers".into(), one("SELECT count(*) FROM servers")?),
        (
            "servers banned".into(),
            one("SELECT count(*) FROM servers WHERE banned = 1")?,
        ),
        ("report rows".into(), one("SELECT count(*) FROM reports")?),
        ("allowlist".into(), one("SELECT count(*) FROM allowlist")?),
    ];
    for kind in KINDS {
        let n = conn.query_row(
            "SELECT count(*) FROM listed WHERE kind = ?1 AND removed = 0",
            [kind],
            |r| r.get(0),
        )?;
        out.push((format!("listed {kind}"), n));
    }
    out.push(("cursor".into(), meta(conn, "seq")?));
    Ok(out)
}
