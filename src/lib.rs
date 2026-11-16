//! UwUSpamNet: mail servers share spam signals — text digests, link domains, sending IPs and
//! sender domains — and fetch a list of what at least three independent servers reported.
//!
//! [`digest`] is Digest v1 (`docs/digest-v1.md`), usable on its own by any mail server.
//! The protocol is in `docs/protocol.md`.

pub mod api;
pub mod db;
pub mod digest;
pub mod net;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

pub const DAY: i64 = 86_400;

/// Seconds since the Unix epoch: the system clock, or a fixed one that tests move by hand.
#[derive(Clone, Default)]
pub struct Clock(Option<Arc<AtomicI64>>);

impl Clock {
    pub fn fixed(at: i64) -> Self {
        Self(Some(Arc::new(AtomicI64::new(at))))
    }

    pub fn now(&self) -> i64 {
        match &self.0 {
            Some(at) => at.load(Ordering::SeqCst),
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
        }
    }

    /// Moves a fixed clock on; does nothing to the system clock.
    pub fn advance(&self, seconds: i64) {
        if let Some(at) = &self.0 {
            at.fetch_add(seconds, Ordering::SeqCst);
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    /// Reports one server may send per UTC day.
    pub reports_per_day: u32,
    /// Registrations one client IP may make per UTC day.
    pub registrations_per_ip: u32,
    /// Take the client address from the last `X-Forwarded-For` entry (behind a reverse proxy).
    pub trust_forwarded: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            reports_per_day: 5000,
            registrations_per_ip: 5,
            trust_forwarded: false,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Mutex<rusqlite::Connection>>,
    pub config: Config,
    pub clock: Clock,
    /// Registrations per client IP today. In memory only: no reporter IP is ever written to disk.
    pub registrations: Arc<Mutex<(i64, HashMap<IpAddr, u32>)>>,
}

impl AppState {
    pub fn new(conn: rusqlite::Connection, config: Config, clock: Clock) -> Self {
        Self {
            db: Arc::new(Mutex::new(conn)),
            config,
            clock,
            registrations: Arc::default(),
        }
    }
}

/// RFC 3339 in UTC, e.g. `2026-11-16T12:00:00Z`.
pub fn rfc3339(t: i64) -> String {
    let (days, secs) = (t.div_euclid(DAY), t.rem_euclid(DAY));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn rfc3339_known_dates() {
        assert_eq!(super::rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(super::rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(super::rfc3339(1_794_830_400), "2026-11-16T12:00:00Z");
    }
}
