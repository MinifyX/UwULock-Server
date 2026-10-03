# File requests

Sends the other way round: you make a link, and somebody without an account uploads files and a
message to you through it — a scan of an ID for the bank, the documents of a new colleague, the
photos of a damage for the insurance. It is encrypted in *their* browser, for your account, so the
server keeps only what it cannot read.

## Making one

*Web vault → File requests → New.*

- **Name** — for you only, to find it again.
- **Title** and **note** — what the sender sees, like "Scan of your ID" and "Both pages, please."
- **Your name** — shown to the sender, if you like.
- **Expires after** — from a day to what the admin allows (90 days by default). 30 days after it
  expired, the server deletes the request with everything that arrived.
- **Submissions** — how many uploads it takes (1 by default), or any number until it expires.
- **Files per submission** and **largest file** — 0 files makes it a request for a message only.
- **Allow a message** — whether the sender may write something.
- **Password** — optional; the sender needs it to open the link. Tell it to them another way than
  the link.

Then copy the link and send it. The part after `#` is the link's secret; it never reaches the
server. You can show the link again any time; *Edit → New link* makes the old one useless.

## What the sender sees

The page of the link shows your title, note and name, asks for the password if there is one, and
takes the files, a message and — if they want — their name and address. Everything is encrypted
before it leaves their browser. They need no account and no app.

## When something arrives

You get a mail (at most one per request every 15 minutes), and the request shows a badge in the
web vault. Open it to read the message, download the files (they are decrypted in your browser),
or **take it over as an item**: a secure note with the message and the sender, and the files as
its attachments — moved on the server, not uploaded again. Then the submission is gone from the
request; so it is when you delete it.

The name and address the sender typed are shown as *not verified*: anybody with the link can type
anything there.

## Limits

- Storage: what arrives counts to your storage on the server (with your attachments and Send
  files), messages included. Files attached into a family item count to the family owners'
  storage. If the admin set a limit and it is full, uploads are refused. One request holds at most
  2 GB in all by default (`fileRequests.maxRequestMb`, 0 for no cap); then new submissions are
  refused.
- A request that is switched off or runs out takes nothing more, not even the rest of a
  submission that began before.
- An upload that was started but not finished is deleted after a day.
- Abuse: wrong passwords are counted per request (ten, then one more a minute), and one address
  can make ten submissions an hour. Every request that expired, is full, disabled or unknown looks
  the same to whoever tries the link.

File requests are a feature switch (*Admin portal → Vault & features → Features*, [features.md](features.md)); off,
the links and the API answer 404 and nothing is deleted. The admin sets how many one account may
have, how long they may run and how many files a submission may bring (*Admin portal → Vault & features →
Storage & limits*).

## How it is encrypted

The owner's browser makes a 16-byte secret for the link. From it comes the link key, which
encrypts the request's public details: title, note, owner, and the account's public key. The
sender's browser encrypts for that key — taken from the link, not from the server, so the server
cannot swap in one of its own. Each submission has its own key, wrapped for the account's public
key; each file has its own key under that, so taking a file into an item only wraps its key again.
The label and the link's secret are kept for the owner under the account's extras key, which
survives a key rotation by any client and which the server can't swap for one of its own. Before
showing or copying a link, the web vault checks that its details name the account's own public
key; a request whose details name another key gets no link and needs a new one (*Edit*). The
details are in [uwu-api.md](uwu-api.md) §11.

## On a send domain

When the server has send domains (a later version), a request's link can point there instead:
`https://send.example.com/r/<id>#<secret>`. That page is the same; the send domain answers only
what it needs.
