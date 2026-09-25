# Security

UwULock Server keeps people's password vaults — encrypted by their clients, so it cannot read
them, but a flaw here matters all the same. Thank you for looking.

## Reporting

Please report a vulnerability privately, through GitHub:
**[Report a vulnerability](https://github.com/MinifyX/UwULock-Server/security/advisories/new)**.
Not in a public issue.

Say what you found, how to reproduce it, and what you think it allows. I answer within a week,
and I will tell you when a fix is out and credit you in the release notes unless you would rather
not be named.

## What is in scope

- The server: this repository, and the images at `ghcr.io/minifyx/uwulock-server`.
- `install.sh` and `update.sh`, which run as root.
- Where the server speaks Bitwarden's protocol differently from Bitwarden's own server in a way
  that weakens a client. A flaw in UwULock itself belongs to
  [UwULock-Client](https://github.com/MinifyX/UwULock-Client); one in Bitwarden's clients to
  Bitwarden.

## Supported versions

The newest release. Updating is `sudo bash update.sh`.
