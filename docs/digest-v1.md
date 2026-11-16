# Digest v1

A digest is a short, non-reversible fingerprint of the readable text of a mail. Two mails that
differ only in numbers, links, addresses, case, punctuation or spacing have the same digests.
The reference implementation is `src/digest.rs` (`uwuspamnet::digest`); `digest-v1-vectors.json`
holds test vectors every implementation must pass.

## Input

The readable text of the mail as a Unicode string: the `text/plain` part, otherwise text
obtained from the HTML part. How HTML becomes text is up to the client, but it should keep
paragraph breaks as blank lines, since paragraphs are digested on their own.

## Normalization

`normalize(text)`:

1. Unicode **NFKC**, then the full default **lowercase** mapping (Unicode `SpecialCasing`
   included, e.g. `İ` → `i̇`, final sigma `Σ` → `ς` at the end of a word; no locale rules).
2. Split the result at every character with the Unicode property `White_Space`. For each token:
   - if it contains `://`, starts with `www.` or contains `@`, drop the whole token (URLs and
     e-mail addresses);
   - otherwise delete every character of General Category `N` (`Nd`, `Nl`, `No`: all digits and
     numerals, e.g. `²`, `Ⅻ`).

   Join the tokens with one space (U+0020).
3. Replace every character that is not `Alphabetic` (Unicode derived property) with a space,
   then collapse runs of spaces to one and trim both ends.

The result consists of letters and single spaces only.

## Digests

- **Whole text**: if `normalize(text)` has at least **40** characters (Unicode scalar values,
  not bytes), emit `d1:` + the first 32 hex digits (lowercase) of SHA-256 over its UTF-8 bytes.
- **Paragraphs**: replace `CRLF` and lone `CR` in the *input* by `LF` and split it into lines
  at `LF`. A line is blank if it is empty or consists of `White_Space` only. A paragraph is a
  maximal run of non-blank lines (joined with `LF`). Normalize each paragraph on its own as
  above. Of those with at least **60** characters, take them longest first (equal lengths in
  input order), skip one whose digest was already taken, and stop at **4**. Each gives `p1:` +
  the first 32 hex digits of SHA-256 of the normalized paragraph.

Output order: the `d1:` digest (if any), then the `p1:` digests in the order taken. A text may
have no digest at all.

Valid digest: `d1:` or `p1:` followed by exactly 32 characters from `0-9a-f`.

## Notes for implementers

- Unicode tables differ a little between versions. The vectors use only characters whose
  properties are stable; text in very new scripts may hash differently across implementations,
  which only means a missed match.
- Combining marks (General Category `M`) are `Alphabetic` in some cases and not in others.
  Implementations must use the `Alphabetic` property, not "category L", to agree with the
  reference; NFKC composes most accented letters before this matters.
- Step 2 works on tokens, so `example.com/path` without a scheme or `www.` is not treated as a
  URL: its letters stay (`example com path`). This is deliberate and keeps the rule simple.
