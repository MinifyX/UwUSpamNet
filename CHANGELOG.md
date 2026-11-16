# Changelog

## 0.1.0

First version.

- Protocol v1: `POST /v1/register`, `POST /v1/reports`, `GET /v1/list` (full and incremental
  with cursor and `removed`), `GET /v1/health`, information and privacy page at `/` (German and
  English).
- Listing rules: at least 3 registration networks (/24, /48) within 14 days, spam ≥ 3 × ham,
  score 1.0–4.0, person reports count double, expiry after 14 days, sooner with ham.
- Allowlist with a seed of freemail, brand and carrier domains; admin commands `servers`,
  `ban`, `unban`, `allowlist`, `stats`.
- Digest v1 specification with test vectors, and the reference implementation as
  `uwuspamnet::digest`.
- Container image (distroless, unprivileged, read-only) for amd64 and arm64.
