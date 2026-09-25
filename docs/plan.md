# Plan: UwULock Server

Ein eigener, selbst gehosteter Server für [UwULock](https://github.com/MinifyX/UwULock-Client):
Bitwarden-kompatibel wie Vaultwarden, aber schneller, auf UwULock zugeschnitten, und mit Platz
für eigene Funktionen — ohne dass die offizielle Bitwarden-Browsererweiterung, die Apps oder die
CLI aufhören zu funktionieren.

Stand: September 2026. Stufe 0 ist fertig (0.0.1).

## Leitlinien

- **Zero-Knowledge wie bei Bitwarden.** Der Server sieht nie ein Passwort und nie einen Eintrag im
  Klartext, nur das, was die Clients verschlüsselt haben.
- **Die offiziellen Clients sind der Maßstab.** Browsererweiterung, Handy-Apps, Desktop-App und
  `bw`-CLI müssen immer funktionieren. Eigene Funktionen liegen deshalb unter `/uwu/v1/…`, wo die
  offiziellen Clients nie hinschauen.
- **Eine Datei, ein Container.** SQLite, ein Docker-Image, `install.sh` und `update.sh` wie bei
  UwUSync. PostgreSQL kommt später als zweites Backend hinter derselben Schicht.
- **Keine Favicon-Abfragen bei Dritten** (UwULock-Vision): `/icons/…` liefert nichts, die
  Erweiterung zeigt dann ihr Standard-Symbol.

## Aufbau

| Crate / Ordner   | Was es macht |
| ---------------- | ------------ |
| `uwulock-store`  | Datenbank: SQLite mit einer Schreib- und mehreren Leseverbindungen, Migrationen, Backup und Restore. Alles darüber spricht nur mit `Store`, nie direkt mit SQLite — so kann PostgreSQL später daneben. |
| `uwulock-api`    | HTTP: Bitwarden-API (`/identity`, `/api`, `/notifications`, …) und UwULocks eigene unter `/uwu/v1`. |
| `uwulock-server` | Das Programm: Einstellungen, TLS (Let's Encrypt, Zertifikatsdateien oder hinter einem Proxy), Befehle, nächtliche Backups, Update-Hinweis. |
| `uwulock-bench`  | Last gegen einen Bitwarden-kompatiblen Server, zum Vergleich mit Vaultwarden. |
| später `uwulock-notify`  | Echtzeit: SignalR-WebSocket für die offiziellen Clients, Bitwardens Push-Relay für die Handy-Apps, ein schlanker Kanal für UwULock. |
| später `uwulock-mail`    | SMTP, Vorlagen auf Deutsch und Englisch, Voreinstellung für UwUMail-Server. |
| später `uwulock-migrate` | Übernahme eines Vaultwarden direkt aus dessen Datenbank. |
| später `web/`            | Eigener Web-Vault und Admin-Portal (React). |

Die Krypto kommt aus dem Client: `uwulock-core` (im Repository des Clients) enthält Bitwardens
Verschlüsselung ohne Netzwerk und lässt sich nach WebAssembly bauen. Der Web-Vault nutzt dieselbe,
gegen Bitwardens SDK-Testwerte geprüfte Krypto wie der Desktop-Client, und die Tests des Servers
können als echter UwULock-Client gegen ihn laufen.

## Was „schneller als Vaultwarden" heißt

- `/api/sync` mit wenigen Abfragen: eine pro Tabelle statt einer pro Eintrag, die Antwort
  gestreamt und komprimiert.
- `/api/accounts/revision-date` — das fragen die Clients ständig — aus dem Speicher.
- SQLite im WAL-Modus: Lesen wartet nie auf Schreiben.
- Anmeldung: Vaultwarden hasht bei jeder Anmeldung noch einmal mit PBKDF2 und 600.000 Runden. Hier
  Argon2id, ähnlich sicher, weniger CPU. Übernommene Vaultwarden-Hashes werden bei der nächsten
  Anmeldung umgestellt.
- Gemessen, nicht behauptet: `uwulock-bench` und `.github/workflows/bench.yml` vergleichen mit
  Vaultwarden auf derselben Maschine, [docs/performance.md](performance.md) hält die Zahlen fest.
- Für UwULock (Stufe 6): Delta-Sync, nur was sich seit dem letzten Mal geändert hat.

## Stufen

Jede Stufe ist ein Release und für sich nutzbar.

### Stufe 0 — Grundlage (0.0.1, fertig)

- [x] Repository, Workspace, CI (fmt, clippy, Tests, Audit, Image-Scan)
- [x] Docker-Image amd64 + arm64, `install.sh` (Let's Encrypt oder hinter einem Proxy) und
      `update.sh` mit Kanälen latest / beta / edge und Rückweg, wenn eine Version nicht hochkommt
- [x] TLS: Let's Encrypt über TLS-ALPN-01 (nur Port 443), Zertifikatsdateien mit Neuladen, oder
      Klartext hinter einem Proxy; in CI gegen Pebble getestet
- [x] Datenbank-Schicht mit Migrationen, Backups (nächtlich, vor jedem Update, sieben behalten),
      Restore
- [x] Health-Check, `/alive`, `/api/now`, Update-Hinweis im Log
- [x] Benchmark-Werkzeug und wöchentlicher Vergleich mit Vaultwarden
- [x] Im Client: `uwulock-bitwarden` in `uwulock-core` (Krypto, WASM-fähig) und die HTTP-Schicht
      aufgeteilt

### Stufe 1 — Kern für Einzelne (0.1)

- Anmeldung: Prelogin, Registrierung nur per Einladung (optional frei für bestimmte Domains),
  Token mit Passwort und Refresh-Token, Geräte
- Tresor: Sync, Einträge anlegen/ändern/löschen, Papierkorb, Favoriten, Massenaktionen, Import,
  Ordner, Profil
- Konto: Passwort, KDF und E-Mail ändern, Schlüssel rotieren, Konto löschen
- `/api/config` mit einer Version, bei der die offiziellen Clients ihre Funktionen freischalten
- 2FA: TOTP, E-Mail-Code, Wiederherstellungscode, „Gerät merken"
- CORS für die Browsererweiterung, Rate-Limits, Header-Timeouts
- Prüfstein: UwULock-Client, Browsererweiterung, `bw`-CLI und Handy-Apps funktionieren

### Stufe 2 — Umstieg von Vaultwarden (0.2)

- `uwulock-server import-vaultwarden /pfad/zu/data`: Konten, Geräte samt Refresh-Tokens und
  Vaultwardens `rsa_key` (Geräte bleiben angemeldet), 2FA, Ordner, Einträge, Anhänge, Sends,
  Notfallzugriffe. Vorhandene Organisationen werden übernommen und im Sync mitgeliefert.
- Echtzeit: SignalR-Hub, Push-Relay für die Handy-Apps
- Ab hier kann der eigene Tresor umziehen.

### Stufe 3 — Web-Vault und Admin-Portal (0.3)

- Web-Vault: Tresor im Browser, Krypto über WASM, Einstellungen, 2FA einrichten
- Admin-Portal: Nutzer, Einladungen, Geräte, 2FA zurücksetzen, SMTP, Push-Relay,
  Registrierungsregeln, Statistik, Logs, Backups, Update-Hinweis
- Admins sind normale Konten mit Admin-Recht; den ersten legt die Kommandozeile an
- Deutsch und Englisch

### Stufe 4 — Alles, was Vaultwarden für Einzelne kann (1.0)

- Anhänge, Sends (Text und Datei, öffentlicher Link)
- Notfallzugriff
- WebAuthn / FIDO2 als zweiter Faktor, Anmeldung mit Passkey
- „Mit Gerät anmelden", API-Keys für die CLI
- Sicherheitsprüfung wie beim Client

### Stufe 5 — Firma

- Organisationen, Sammlungen, Rollen, Einladungen
- Gruppen, Richtlinien (2FA-Pflicht, Master-Passwort-Anforderungen, Account-Recovery)
- Ereignisprotokoll / Audit
- PostgreSQL
- SSO über OIDC (Entra ID), Bitwarden Directory Connector (LDAP, Entra)

### Stufe 6 — UwU-Extras (unter `/uwu/v1`, angekündigt unter `GET /uwu/v1/info`)

- Schlanker Echtzeit-Kanal und Delta-Sync für den UwULock-Client
- Suite-Tresor: eigene verschlüsselte Objekte für SSH-Hosts, RDP-Verbindungen, UwUMail-Konten —
  bewusst nicht in Bitwardens Eintragsliste, weil unbekannte Typen die offiziellen Clients
  stören könnten
- UwUSync ersetzen: UwUSSH und UwURDP synchronisieren über UwULock Server, mit Übernahme aus der
  UwUSync-Datenbank
- Passwort-Gesundheit: Der Client rechnet (der Server kennt keine Passwörter); der Server bietet
  einen HIBP-Proxy mit k-Anonymität und hebt den Bericht verschlüsselt auf

## Kompatibilität absichern

- In CI: die offizielle `bw`-CLI gegen den Server (Anmeldung, 2FA, Sync, Einträge, Anhänge, Sends)
  und die Flow-Tests aus `uwulock-bitwarden` gegen den echten Server
- Wöchentlich die neuesten Bitwarden-Clients dagegen; bricht etwas, entsteht ein Issue
- Vor jedem Release eine Checkliste für Browsererweiterung und Apps (Autofill, Passkeys, Push)

## Release

Docker-Images für amd64 und arm64 auf GHCR, dazu `install.sh`, `update.sh`, `compose.yaml` und
`env.example` mit Prüfsummen am GitHub-Release; CHANGELOG und Tags wie bei UwUMail-Server.

## Festgelegt

- Stufe 5 (Firma) vor Stufe 6 (UwU-Extras); die beiden lassen sich tauschen.
- Web-Vault an der Wurzel `/`, Admin-Portal unter `/admin`.
- Anhänge auf der Platte; S3-artiger Speicher erst, wenn die Firma ihn braucht.
- AGPL-3.0, Registrierung nur per Einladung, Deutsch und Englisch.
