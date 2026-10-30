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
  asked for as after a password. A code by mail works too (since 0.8.0-beta.3), and so does
  *remember this device*, for the same days as after a password (*Security & sign-in → Sign-in*).
- **The admin's two-step and master password rules** also hold for accounts made before them: the
  next login asks for the second step to be set up (password or SSO); the web vault asks for a new
  master password after the next login or unlock when the old one breaks the rules and
  *enforce on login* is on. Bitwarden's own apps check that rule only after a password login.
- **Logging out at the provider** logs out the SSO sessions here too (back-channel logout, since
  0.8.0-beta.3): their tokens end at once and open apps are told (`ssoLogout`). Devices that logged
  in with the master password stay logged in.
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

Since 0.8.0-beta.3 the pairing also tells UwUAuth the back-channel logout address
(`https://<your server>/identity/connect/backchannel-logout`). **Pairings made before have to be
made again** (*Entkoppeln*, delete the app in UwUAuth, pair again) for a logout at UwUAuth to reach
UwULock; until then, SSO logins keep working, only the logout does not come through.

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

For **back-channel logout**, enter `https://<your server>/identity/connect/backchannel-logout` as
the client's back-channel logout URI at the provider (Keycloak: *Backchannel logout URL*, with
*session required* on; Authentik: *Back-channel logout URL*). The provider has to put `sid` into
the ID token or `sub` into the logout token.

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
- A **logout token** (back-channel logout, OpenID Connect Back-Channel Logout 1.0) is checked like
  an ID token — signature against the provider's keys (never `none`), issuer, audience — and must
  be at most five minutes old, have the logout event, no `nonce`, and `sub` or a `sid` this server
  saw at an SSO login. Each `jti` is taken once; a token sent again is refused. The answer is 200
  (also when the account is unknown) or 400, never cached. It nulls the refresh tokens of the
  account's SSO devices and ends their sessions; the event log gets `sso-logout`.
- The mail with a code for the second step after SSO needs the short-lived token from the SSO
  login's answer (`SsoEmail2faSessionToken`, five minutes) instead of the password; a wrong or
  stale token gets one answer for every cause, and the login limits count as for a password.
- The client secret is kept encrypted, under a key in `secret.key` in the data directory (made on
  first use, readable only by the server). The off-site backups take the file along; a database
  copy alone does not open it. After a restore onto a new machine from a *local* backup, enter
  the secret again (or pair again).
- Changing who may log in asks for the admin's master password: the issuer, the client id or
  secret, *trust unverified addresses*, the extension ids, switching SSO on or off, and pairing.
  So does changing who becomes an admin — the admin group and the claims with the groups or the
  roles (a claim people set themselves, like their name, would make anybody an admin) — and a new
  SCIM token, and what SCIM does when it deletes somebody, and who may make an account through SSO
  (the sign-ups and the user group: *group* without a user group lets everybody at the provider
  in). So do *make admin* and *reset second
  step* on the users page. A stolen admin session alone can't point SSO at another provider, or
  keep power over accounts after it is gone.
- **The SCIM token acts with admin rights:** it finds every account by its address and can disable
  it, or delete it with its vault when *Konto und Tresor löschen* is chosen — every account but the
  last admin, not only those SCIM made. Keep it like an admin password, and make a new one if it
  may have leaked.
- SCIM tokens are kept as their SHA-256 and compared in constant time; wrong tokens are counted per
  address, and after 30 the address waits.
- Every SSO sign-up, linking, admin change and SCIM change is in the event log.
