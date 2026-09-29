# Sharing: an item as a Send, Sends for given addresses, and the 2FA report

## Share an item as a Send

*Web vault → an item → Share as Send* (the Send button beside the star) makes a text Send out of the item:
you tick which values go in — username, password, websites, notes, custom fields, a card's or an
identity's fields, an SSH key — and each becomes a line `Label: value` under the item's name.
**The authenticator key (TOTP) is never among them**, whatever is ticked: whoever has it can make
the codes for good, which is not what "share this login" means.

It is an ordinary Send, so it also shows up under *Sends*, in the UwULock app and in the official
Bitwarden apps. What it starts with:

- it goes after **one day** (and stops opening then),
- it opens **once**,
- anybody with the link may open it — or only with a **password**, or only **given addresses**
  (below).

The link appears at once, with a button to copy it. Send it another way than the password, if it
has one.

Everything happens in the browser: the values are put together and encrypted there, with a key
that only travels in the link after the `#`. The server stores what it cannot read.

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
