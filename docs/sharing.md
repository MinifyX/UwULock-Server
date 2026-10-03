# Sharing: an item as a Send, Sends for given addresses, and the 2FA report

## Share an item as a Send

*Web vault → an item → Share as Send* (the Send button beside the star) makes a Send out of the
item: you tick which values go in — username, password, websites (each listed with its address,
so several can be told apart), notes, custom fields, a card's or an identity's fields, an SSH key
— and, for a login with an authenticator key, **the one-time codes**. Those are never ticked at
the start.

It is an **entry Send**: an ordinary text Send whose text is two things.

- The readable lines, `Label: value` under the item's name, for the official Bitwarden apps and
  anybody who opens it there. **The authenticator key is never among them.**
- A last line `uwulock-entry:v2:<base64url(JSON)>.<base64url(tag)>` with the same values as JSON —
  `{name, username?, password?, websites[], notes?, fields[{name, value, hidden}], totp?}`
  (uwulock-core `entry_send`; the same contract in the web vault's WebAssembly and the apps;
  details in UwULock-Client's docs/uwu-extras.md, "Contract (v2)"). The tag is an HMAC-SHA256 of
  the line, keyed from the Send's secret — the part of the link after `#` — so only the Send's
  own last line counts: a marker line that sat in an item's notes, or one from another Send, has
  no valid tag and the text shows as plain text.

UwULock's Send page sees that line, hides the raw text and shows the item the way the vault does:
each value with a copy button, the password and hidden fields as dots until a click, websites as
links (only `http`/`https` ones; anything else is text to copy). Until the line is read the page
shows "…", never the raw text; *Show original text* shows the readable lines, and every Copy on
the page takes the value off the clipboard again after the vault's time. Names and values keep
their own writing direction, so bidi characters can't reorder what is around them. With the codes chosen, `totp` holds the key **only so the page can make the codes**: it
shows the current code counting down and, in the last 10 seconds, the next one ("Next: 123 456")
with its own copy button — never the key, never a QR code. But the key travels in the Send: the
choice says *One-time codes (with their key)*, and ticking it asks once more — "the one-time
code's key travels in the Send, encrypted; whoever has the link can read out the key and keep
making codes with it, even after the Send is deleted" — with *Better not* as the default. A text without the marker, with another version or one
that does not decode is shown as the plain text it is; Sends made before 0.8 stay as they were.
In your own list (*Sends*) an entry Send shows its readable lines, marked *shared as an item*. Its
text can't be edited there (the last line would still carry the old values): to take something
back, delete the Send and share the item again.

It shows up under *Sends*, in the UwULock app and in the official Bitwarden apps. What it starts
with:

- it goes after **one day** (and stops opening then),
- it opens **once**,
- anybody with the link may open it — or only with a **password**, or only **given addresses**
  (below).

The link appears at once, with a button to copy it. Send it another way than the password, if it
has one.

Everything happens in the browser: the values are put together and encrypted there, with a key
that only travels in the link after the `#`. The server stores what it cannot read — to it an
entry Send is a text Send like any other.

## Sends only for given addresses

In the Send editor (and when sharing an item), *Who may open it?* offers **Only certain
addresses**. Whoever opens the link is asked for their email address; if it is on the list, the
server mails them a six-digit code, and only with that code does it hand out the Send. This is
Bitwarden's "Send with email verification", so the newest Bitwarden apps show and open such Sends
too.

- **It needs mail.** Without a mail server in the admin portal, the option is greyed out, and the
  server refuses such Sends.
- **The server knows the addresses** — it has to, to mail the codes. The Send's content it still
  cannot read.
- The page says the same whether an address is on the list or not, and only listed addresses get
  a mail, so nobody learns the list by trying.
- A code works for **five minutes, once**. Five wrong codes end it; an address gets at most one
  mail a minute and five an hour per Send, on top of the server's usual limits for requests from
  one network and mails to one address.
- A password and addresses exclude each other. *Remove addresses* (or *Remove password*) makes
  the Send open for anybody with the link again.
- Clients that still open Sends the old way, without asking the identity endpoint for a token
  first, cannot open such a Send; they are told to use the web vault or a current app.

The mail comes in the server's default language, with its [branding](branding.md).

## The report "2FA possible, not set up"

The password check (*Web vault → Password check*) also lists logins for websites that offer
two-step login with an authenticator app, but have no authenticator key stored in the item — with
a link to the website's own instructions. Add the key to the item once you set it up, and the
vault shows the codes.

Which websites offer what comes from [2FA Directory](https://2fa.directory/), whose list is MIT
licensed (© 2factorauth and contributors). **The server mirrors it** — it fetches
`https://api.2fa.directory/v3/all.json` the first time somebody opens the report, then once a
day, through the same checked connection as website icons — and **the comparison happens in the
browser**: the server never learns which websites are in a vault, and the browser never talks to
2FA Directory. A login is matched by its first website's host, or a domain above it
(`login.example.com` finds `example.com`).
