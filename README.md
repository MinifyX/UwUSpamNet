# UwUSpamNet

Mail servers share spam signals: each one reports what it recognised as spam (or what a person
said was not spam), and fetches a list of what at least three independent servers reported.
Open to any mail server software, not only [UwUMail](https://github.com/MinifyX/UwUMail-Server).
Public instance: `https://spamnet.uwu.minifyx.de`.

## What is shared

Signals only:

- `digest`: text fingerprints, a truncated SHA-256 of normalized text ([Digest v1](docs/digest-v1.md)), not reversible;
- `domain`: registrable domains from links in the mail;
- `ip`: the address that delivered the mail (IPv4 as is, IPv6 as its /64);
- `from`: the registrable RFC5322.From domain;
- `spam` or `ham`, and whether a person or a filter decided.

**Never shared**: message contents, subjects, recipient addresses, full sender addresses, names,
attachments, filter word lists. The service stores no addresses of reporting servers apart from
the network they registered from (/24 or /48).

## How listing works

An entry is listed once servers from at least 3 different registration networks reported it
as spam within 14 days, and spam outweighs ham at least 3 to 1. Its score runs from 1.0 to 4.0
with the number of networks (a person's report counts double a filter's). Entries expire 14 days
after the reports stop; ham makes them go sooner. Big brands, parcel carriers and freemail
providers are on an allowlist and never listed. Details: [docs/protocol.md](docs/protocol.md#listing-rules).

## Joining

1. `POST /v1/register` with your server's name and software, once. Keep the key: it is shown
   only once.
2. `POST /v1/reports` in batches when your users move mail to or out of Junk, or your filter
   rejects.
3. `GET /v1/list?since=<cursor>` every 15 minutes and score mail with what is listed.

The whole API, limits and error codes: [docs/protocol.md](docs/protocol.md). Tell your users
that you share these signals (UwUMail Server ships a text for its operators' privacy notice).

## Running your own

```sh
cp .env.example .env     # optional
docker compose up -d     # ghcr.io/minifyx/uwuspamnet, port 8080 on 127.0.0.1
```

Put a reverse proxy with TLS in front, e.g. Caddy:

```
spamnet.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

and set `SPAMNET_TRUST_FORWARDED=true`, so the registration limit sees the client, not the proxy.
Without Docker: `cargo build --release`, then `uwuspamnet --data /var/lib/uwuspamnet --listen 127.0.0.1:8080`.

| setting | flag | default |
|---|---|---|
| `SPAMNET_DATA` | `--data` | `data` (`/data` in the image); the database is `spamnet.db` in there |
| `SPAMNET_LISTEN` | `--listen` | `127.0.0.1:8080` (`0.0.0.0:8080` in the image) |
| `SPAMNET_TRUST_FORWARDED` | `--trust-forwarded` | off |
| `SPAMNET_REPORTS_PER_DAY` | `--reports-per-day` | 5000 |
| `SPAMNET_REGISTRATIONS_PER_IP` | `--registrations-per-ip` | 5 |

Administration, with the same binary (in Docker: `docker compose exec spamnet uwuspamnet …`):

```
uwuspamnet servers                              # registered servers
uwuspamnet ban s_…  /  uwuspamnet unban s_…     # a banned server's reports stop counting
uwuspamnet allowlist add domain example.com --note "why"
uwuspamnet allowlist add ip 192.0.2.0/24
uwuspamnet allowlist remove from example.com
uwuspamnet allowlist list
uwuspamnet stats
```

Back up `/data/spamnet.db` (SQLite, WAL). Losing it only means servers register again and the
list builds up anew.

### Seed allowlist

A new database starts with these for both `domain` and `from` (note `seed`; remove any with
`allowlist remove`). Subdomains are covered too.

- Freemail: gmail.com, googlemail.com, outlook.com, hotmail.com, live.com, yahoo.com,
  icloud.com, me.com, aol.com, gmx.de, gmx.net, web.de, t-online.de, freenet.de, posteo.de,
  mailbox.org, proton.me, protonmail.com
- Brands: google.com, microsoft.com, apple.com, amazon.com, amazon.de, paypal.com, ebay.com,
  ebay.de, facebook.com, instagram.com, linkedin.com, github.com, youtube.com
- Parcel carriers: dhl.de, dhl.com, deutschepost.de, dpd.de, dpd.com, hermesworld.com,
  myhermes.de, gls-group.eu, ups.com, fedex.com

Freemail is there because spammers use free accounts: listing the provider would hit everybody
on it. Brands and carriers are what phishing imitates; their own domains turn up in phishing
mails as links next to the bad one.

## Development

```sh
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

Tests run the router in-process with an in-memory database and a fixed clock.

## Licence

[AGPL-3.0](LICENSE).
