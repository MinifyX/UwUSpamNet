# Security

Please report vulnerabilities privately through GitHub's
[security advisories](https://github.com/MinifyX/UwUSpamNet/security/advisories/new), not in a
public issue. You get an answer within a week.

In scope: the service in this repository, its container image and the public instance at
`spamnet.uwu.minifyx.de`. Of special interest: ways to get a value listed without three
independent registration networks, ways to keep a value off the list, ways to read anything a
server sent beyond the published list, and ways to exhaust the service.

Please do not test against the public instance with volume; run your own (`docker compose up`).
