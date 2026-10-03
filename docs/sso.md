# Logging in through UwUAuth or another provider (SSO)

UwULock Server can let people log in through an OpenID Connect provider: [UwUAuth](https://github.com/MinifyX/UwUAuth-Server),
or any other — Keycloak, Authentik, Entra ID, Google, … SSO says *who* somebody is. The vault is
still opened with the master password, which never leaves the person's device: not the server and
not the provider can open it. Logging in with the password keeps working beside it, unless the
admin says otherwise.

- [What people see](#what-people-see)
- [Pairing with UwUAuth](#pairing-with-uwuauth)
- [Any other provider](#any-other-provider)
- [Who may sign up, and who is an admin](#who-may-sign-up-and-who-is-an-admin)
- [SCIM](#scim)
- [Security](#security)

## What people see

- **Web vault and admin portal:** a button *Log in with …* (the label is the admin's) on the login
  page. The first time, somebody without an account sets their master password right after; the
  next time, SSO logs them in and the master password unlocks the vault.
- **Bitwarden's apps** (browser extension, desktop, phones, `bw login --sso`): *Log in with single
  sign-on*, with **any** SSO identifier — the server has only one provider. The apps open the web
  vault, which passes the login on to the provider, and come back logged in; a new account sets
  its master password in the app.
- **Two-step login** set up on the account still applies after SSO: the code (or security key) is
  asked for as after a password.
- An existing account is **linked** the first time somebody logs in through SSO with its address —
  only if the provider says the address is verified. The account gets a security notice
  (*a login through … was linked*). After that, the account is found by the login at the
  provider, even if the address there changes.

## Pairing with UwUAuth

UwUAuth 0.4 and newer pair with a one-time code instead of copying ids and addresses:

1. In UwUAuth: *Apps → Pair a UwUSuite app*. Pick who may use the vault (default: everybody) and,
   if you like, which groups get the roles `admin` (admin portal) and `user` (may make a vault
   without an invitation). UwUAuth shows a code and a QR code, valid for 15 minutes.
2. In UwULock's admin portal: *Security & login → SSO provider → Pair with UwUAuth*, UwUAuth's address and the code
   (or paste the QR code's text, which has both), then your master password.

UwULock then gets its client id and secret, tells UwUAuth its redirect address, its icon, its two
roles and its SCIM address, and switches SSO on with sign-ups by role. UwUAuth starts pushing its
people and groups over SCIM right away. *Entkoppeln* forgets the pairing here and switches SSO
off; delete the app in UwUAuth too (the page links to it).

UwULock has to be reachable at an `https` address for this.

## Any other provider

Make a **confidential client** (with a secret) or a public one with PKCE at the provider:

- **Redirect URI:** `https://<your server>/identity/connect/oidc-signin` (the admin portal shows it)
- **Grant:** authorization code, with PKCE (S256)
- **Scopes:** `openid email profile`, and `groups` if the provider has groups in a scope
- The ID token (or userinfo) needs `email` and `email_verified`; for groups, a claim with their
  names (`groups` by default; Keycloak's `/group` paths are fine).

Then *Anmeldung → OpenID Connect* in the admin portal: issuer (the provider's address, as in its
`/.well-known/openid-configuration`), client id and secret, and switch it on. *Anbieter testen*
reads the discovery document and the keys.

| Provider | Issuer |
| --- | --- |
| Keycloak | `https://sso.example.com/realms/<realm>` |
| Authentik | `https://sso.example.com/application/o/<slug>/` |
| Entra ID | `https://login.microsoftonline.com/<tenant id>/v2.0` |

The provider's address may be in the local network (only an admin can set it). The server follows
no redirects there, reads only https (plain http only on this machine, and only when the issuer
itself is on this machine), and takes ID tokens signed with RS256, RS384, RS512, PS256, PS384,
PS512, ES256, ES384 or EdDSA. The issuer has no `?query` or `#fragment`. When the provider does not
answer, the server remembers that for 30 seconds and asks it once for all logins waiting.

## Who may sign up, and who is an admin

**Sign-ups** (*Wer sich ohne Einladung einen Tresor anlegen darf*):

- *Niemand* — only accounts there are already.
- *Nur mit Einladung oder über SCIM* (the default) — also addresses with an invitation, and
  addresses the provider pushed over SCIM.
- *Wer in der Nutzergruppe ist* — also everybody in the user group; without a group, everybody the
  provider lets through. After pairing: UwUAuth's role `user`.

**Admins:** with an admin group set (or, after pairing, UwUAuth's role `admin`), being an admin
follows the provider at every SSO login: in the group — an admin, out of it — not any more. The
right is only *given* to a login from inside the [admin networks](deployment.md); the last admin
never loses it this way, so nobody is locked out of the portal.

**SSO only** (*Nur noch über SSO anmelden*): the password (and passkey) login then works only for
admins and with the CLI's API key. **Admin portal only with SSO**: admins, too, reach the portal
only after an SSO login; it can be switched on only from an SSO login. The way back in, should the
provider be gone: `uwulock-server settings set sso.adminsOnlyWithSso false` and a restart.

## SCIM

At `https://<your server>/scim/v2` (SCIM 2.0), with a bearer token: pairing brings UwUAuth's, for
other providers *Anmeldung → SCIM → Token erzeugen* shows one once.

- **Users:** a person without an account becomes an address that may sign up through SSO (also
  while sign-ups need an invitation). An account is found by its address. `active: false`
  disables the account — every device is logged out at once, and it cannot log in — and `true`
  enables it again. `displayName` becomes the account's name, `externalId` is kept for lookups.
  A person deleted by the provider is disabled, or — if the admin chose *Konto und Tresor
  löschen* — deleted with the vault. The last admin is neither.
- **The address never changes over SCIM:** it is the salt of the account's keys. Its owner changes
  it in the vault.
- **Groups** are kept to know who is in the admin group; whoever leaves it (or the group goes)
  loses the admin right at once (not the last admin).
- Lookups by `userName eq "…"`, `externalId eq "…"`, `displayName eq "…"`; unknown attributes are
  ignored.

## Security

- The login is tied to the browser that started it (a cookie, `__Host-uwu-sso`), with the
  provider's `state`, a `nonce`, and PKCE both towards the provider and from the client; the
  client's redirect address must be one of the known ones (the web vault's connector page,
  `bitwarden://sso-callback`, a loopback address for native apps and the CLI). The ID token is
  checked: signature against the provider's keys, issuer, audience, time and nonce.
- The code the client gets is used once, lasts five minutes, and is bound to its PKCE challenge.
- The client secret is kept encrypted, under a key in `secret.key` in the data directory (made on
  first use, readable only by the server). The off-site backups take the file along; a database
  copy alone does not open it. After a restore onto a new machine from a *local* backup, enter
  the secret again (or pair again).
- Changing who may log in asks for the admin's master password: the issuer, the client id or
  secret, *trust unverified addresses*, the extension ids, switching SSO on or off, and pairing.
  So do *make admin* and *reset second step* on the users page. A stolen admin session alone
  can't point SSO at another provider.
- **The SCIM token acts with admin rights:** it finds every account by its address and can disable
  it, or delete it with its vault when *Konto und Tresor löschen* is chosen — every account but the
  last admin, not only those SCIM made. Keep it like an admin password, and make a new one if it
  may have leaked.
- SCIM tokens are kept as their SHA-256 and compared in constant time; wrong tokens are counted per
  address, and after 30 the address waits.
- Every SSO sign-up, linking, admin change and SCIM change is in the event log.
