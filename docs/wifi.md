# Wi-Fi networks

UwULock keeps Wi-Fi networks as an item type of its own: in the list with their own icon and
filter (*Wi-Fi*), with an editor for the network's settings and a QR code that phones join the
network with. Bitwarden has no such type, so a network is stored the way every Bitwarden app can
read it: as a **secure note** (cipher type 2) with **custom fields**. Bitwarden's official apps
show a note with fields; every UwULock app (web vault, desktop, Android, iOS, the browser
extension) shows a Wi-Fi network. Nothing on the server knows the difference — the fields are
encrypted like every other.

## The contract

The same in every app. Field names are stable English and never translated; field types are
Bitwarden's (`0` text, `1` hidden, `2` boolean).

| Field | Type | Value |
| --- | --- | --- |
| `uwulock:type` | 0 | `wifi` — the marker. UwULock's apps hide it. |
| `SSID` | 0 | the network's name |
| `Password` | 1 | the network's password (empty for an open network) |
| `Security` | 0 | one of `WPA3`, `WPA2/WPA3`, `WPA2`, `WPA`, `WEP`, `None`, `WPA2-Enterprise`, `WPA3-Enterprise` |
| `Hidden network` | 2 | `true` or `false` |
| `EAP method` | 0 | Enterprise only: `PEAP`, `TTLS`, `TLS` or `PWD` |
| `Phase 2` | 0 | Enterprise only: `MSCHAPV2`, `PAP`, `GTC` or `none` |
| `Identity` | 0 | Enterprise only |
| `Anonymous identity` | 0 | Enterprise only |
| `CA certificate` | 0 | Enterprise only: the server's domain, or a note on the certificate |

The item's notes are the cipher's notes; its name defaults to the SSID.

Rules for every app that reads or writes networks:

- **Recognising**: an item is a network when it is a secure note and has a text field named
  exactly `uwulock:type` whose value is `wifi` (surrounding spaces and case don't matter). A
  login or card with the field stays what it is.
- **Reading**: the first field of each name counts. A field the app doesn't expect for the
  network's security (an `Identity` on a WPA2 network) is not the network's: it stays an
  ordinary custom field.
- **Writing**: the marker and the network's fields first, in the order of the table; the
  Enterprise fields only for an Enterprise security and only with a value. **Every other field
  stays as it is** — name, value, type and order — after the network's fields. A password the
  app never showed is kept (the web vault sends the field's index, not the value).
- **Unknown values** (a security from another app, an EAP method not in the list) are kept and
  shown as they are; an editor offers them as an extra choice.

## In the web vault

- *New → Wi-Fi* makes a network; the filter *Types → Wi-Fi* appears once there is one.
- The editor has the network's name (the item's name follows it as long as it was the SSID),
  the security as a list, the password with the generator, *Hidden network*, and — only for
  WPA2-/WPA3-Enterprise — EAP method, phase 2, identity, anonymous identity and CA certificate.
  Other fields stay under *Custom fields*.
- The details show the network with copy buttons, the password behind the eye, and
  **Share as QR code**: a dialog with the code and the network's name, security and password
  (hidden until the eye is clicked). The code is drawn in the browser with
  [uqr](https://github.com/unjs/uqr) (MIT), the same library as the authenticator setup; the
  network never leaves the page for it. The password is fetched from the vault for the code and
  forgotten when the dialog closes.
- There is no *Connect* button: a browser cannot join a Wi-Fi network. UwULock's mobile apps
  offer it where the system lets them (UwULock-Client).
- Export (*Settings → Export*, Bitwarden JSON) writes the note with every field; importing that
  file again, here or in another UwULock app, gives the network back. Bitwarden's CSV export
  writes the fields as `name: value` lines.

## The QR code

The format phones and most QR scanners understand:

```
WIFI:T:WPA;S:<ssid>;P:<password>;H:true;;
WIFI:T:WPA2-EAP;S:<ssid>;E:<eap>;PH2:<phase 2>;A:<anonymous>;I:<identity>;P:<password>;;
```

- `T` is `WPA` for every WPA, WPA2 and WPA3 personal security, `WEP` for WEP, `nopass` for
  `None` (then without `P`), and `WPA2-EAP` for both Enterprise securities.
- `\`, `;`, `,`, `:` and `"` in a value get a backslash. An SSID made only of hex digits (an
  even number of them) is put in double quotes, or a phone would read it as bytes.
- Parts without a value are left out, `PH2` also for `none`; `H:true` only for a hidden network.

## Imports

1Password (*Wireless Router*, 1PUX and older CSVs), Proton Pass (*Wi-Fi*, JSON and CSV), LastPass
(*Wi-Fi Password* form) and every entry that already carries the marker (KeePass, Bitwarden JSON
and CSV) become networks; see [docs/import.md](import.md). The code is in
`web/src/lib/import/collect.ts` (`Collector.wifi`), the contract in `web/src/lib/wifi.ts`, the
recognition in the list in `web/wasm/src/view.rs` (`is_wifi`).
