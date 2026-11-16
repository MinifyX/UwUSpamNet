//! Digest v1: text fingerprints of a mail, as specified in `docs/digest-v1.md`.
//!
//! The same input gives the same digests in every implementation; the test vectors in
//! `docs/digest-v1-vectors.json` pin that down.

use sha2::{Digest as _, Sha256};
use unicode_normalization::UnicodeNormalization;

/// Minimum length (in Unicode scalar values) of the whole normalized text for a `d1:` digest.
pub const MIN_TEXT: usize = 40;
/// Minimum length of a normalized paragraph for a `p1:` digest.
pub const MIN_PARAGRAPH: usize = 60;
/// At most this many `p1:` digests.
pub const MAX_PARAGRAPHS: usize = 4;

/// Steps 1–3: NFKC, lowercase, drop URL/address tokens and digits, keep only letters.
pub fn normalize(text: &str) -> String {
    let folded: String = text.nfkc().collect::<String>().to_lowercase();
    let mut kept = String::with_capacity(folded.len());
    for token in folded.split(char::is_whitespace) {
        if token.contains("://") || token.starts_with("www.") || token.contains('@') {
            kept.push(' ');
            continue;
        }
        kept.extend(token.chars().filter(|c| !c.is_numeric()));
        kept.push(' ');
    }
    let letters: String = kept
        .chars()
        .map(|c| if c.is_alphabetic() { c } else { ' ' })
        .collect();
    letters
        .split(' ')
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn hash(prefix: &str, text: &str) -> String {
    let sum = Sha256::digest(text.as_bytes());
    let hex: String = sum[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}{hex}")
}

/// Paragraphs of the raw input: maximal runs of non-blank lines.
fn paragraphs(text: &str) -> Vec<String> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    for line in text.split('\n') {
        if line.chars().all(char::is_whitespace) {
            if !current.is_empty() {
                out.push(current.join("\n"));
                current.clear();
            }
        } else {
            current.push(line);
        }
    }
    if !current.is_empty() {
        out.push(current.join("\n"));
    }
    out
}

/// All Digest v1 digests of a text: `d1:` first (if any), then up to four `p1:`.
pub fn digests(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let whole = normalize(text);
    if whole.chars().count() >= MIN_TEXT {
        out.push(hash("d1:", &whole));
    }
    let mut candidates: Vec<(usize, usize, String)> = paragraphs(text)
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let n = normalize(p);
            (n.chars().count(), i, n)
        })
        .filter(|(len, _, _)| *len >= MIN_PARAGRAPH)
        .collect();
    // Longest first; equal lengths in input order.
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut seen = Vec::new();
    for (_, _, n) in candidates {
        if seen.len() == MAX_PARAGRAPHS {
            break;
        }
        let d = hash("p1:", &n);
        if !seen.contains(&d) {
            seen.push(d);
        }
    }
    out.extend(seen);
    out
}

/// Whether a value is a well-formed Digest v1 digest (`d1:` or `p1:` + 32 lowercase hex).
pub fn is_valid(value: &str) -> bool {
    let Some(hex) = value
        .strip_prefix("d1:")
        .or_else(|| value.strip_prefix("p1:"))
    else {
        return false;
    };
    hex.len() == 32 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
