# Plan: UwULock Server

Ein eigener, selbst gehosteter Server für [UwULock](https://github.com/MinifyX/UwULock-Client):
Bitwarden-kompatibel wie Vaultwarden, aber schneller, auf UwULock zugeschnitten, und mit Platz
für eigene Funktionen — ohne dass die offizielle Bitwarden-Browsererweiterung, die Apps oder die
CLI aufhören zu funktionieren.

Stand: September 2026. Stufe 0 ist fertig (0.0.1), Stufe 1 als 0.1-Beta — mit Web-Tresor und
Admin-Portal, die dafür aus Stufe 3 vorgezogen wurden. Stufen 2, 3 und 4 sind zusammen als
0.4.0-beta.1 erschienen, nach einem Sicherheitsreview
([docs/security-review-2026-09.md](security-review-2026-09.md)); passend dazu UwULock
0.2.0-beta.3. Als Nächstes: Tests auf echten Geräten, dann Stufe 5.

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
| `uwulock-mail`   | SMTP, Vorlagen auf Deutsch und Englisch. |
| `uwulock-web`    | Die Dateien von Web-Tresor und Admin-Portal, in die Binary eingebettet. |
| `uwulock-e2e`    | UwULocks eigener Client (`uwulock-bitwarden`) gegen den echten Server. |
| `web/`           | Eigener Web-Tresor und Admin-Portal (React, im Look der UwULock-App); `web/wasm` ist ihre Krypto: `uwulock-core` als WebAssembly. |
| später `uwulock-notify`  | Echtzeit: SignalR-WebSocket für die offiziellen Clients, Bitwardens Push-Relay für die Handy-Apps, ein schlanker Kanal für UwULock. |
| später `uwulock-migrate` | Übernahme eines Vaultwarden direkt aus dessen Datenbank. |

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

### Stufe 1 — Kern für Einzelne, mit Web-Tresor und Admin-Portal (0.1, Beta)

- [x] Anmeldung: Prelogin, Registrierung nur per Einladung (Link per Mail oder von Hand), Token
      mit Passwort und Refresh-Token, Geräte
- [x] Tresor: Sync, Einträge anlegen/ändern/löschen, Papierkorb, Archiv, Favoriten,
      Massenaktionen, Import, Ordner, Profil
- [x] Konto: Passwort, KDF und E-Mail ändern, Schlüssel rotieren, überall abmelden, Konto löschen
- [x] `/api/config` mit einer Version, bei der die offiziellen Clients ihre Funktionen freischalten
- [x] 2FA: TOTP, E-Mail-Code, Wiederherstellungscode, „Gerät merken"
- [x] CORS für die Desktop-App, Rate-Limits, Header-Timeouts
- [x] Mail (vorgezogen): SMTP, Vorlagen auf Deutsch und Englisch, Sprache pro Konto
- [x] Web-Tresor (vorgezogen aus Stufe 3): Registrieren per Einladung, Tresor ansehen und
      bearbeiten, Mehrfachauswahl, Generator, Import/Export (Bitwarden-JSON und -CSV), alle
      Kontoeinstellungen, 2FA mit QR-Code, Geräte; Krypto über WASM; Deutsch und Englisch
- [x] Admin-Portal (vorgezogen aus Stufe 3): Nutzer, Einladungen, Geräte, 2FA zurücksetzen,
      Admin-Recht, SMTP und weitere Einstellungen in der Datenbank, Statistik, Ereignisse, Logs,
      Backups, Update-Hinweis; den ersten Admin lädt die Kommandozeile ein
- [x] Prüfstein in CI: UwULock-Client (`uwulock-e2e`), die offizielle `bw`-CLI, Web-Tresor und
      Admin-Portal im Browser
- [ ] Vor 0.1.0: Browsererweiterung und Handy-Apps von Hand gegen die Beta (Checkliste unten)

### Stufe 2 — Umstieg von Vaultwarden (0.4, Beta)

- [x] `uwulock-server import-vaultwarden /pfad/zu/data [--dry-run] [--admin …]`: Konten (alter
      PBKDF2-Hash, bei der nächsten Anmeldung Argon2id), Geräte samt Refresh-Tokens (von
      Vaultwarden signierte werden mit dem öffentlichen Teil seines `rsa_key` einmal angenommen
      und ersetzt — Geräte bleiben angemeldet), „Gerät merken", 2FA (App, Mail, Security-Keys aus
      webauthn-rs), Ordner, Einträge, Favoriten, Archiv, Anhänge, Sends, Notfallzugriffe. Eine
      Transaktion, vorher ein Backup. Getestet gegen einen echten Vaultwarden 1.37.3 (CI-Job,
      per Bitwardens CLI gefüllt) und eine daraus gewonnene Fixture.
- [x] Organisationen mit Sammlungen, Gruppen, Richtlinien werden übernommen und im Sync
      mitgeliefert; Mitglieder mit Schreibrecht legen Einträge an, ändern, teilen, hängen Dateien
      an. Verwalten (einladen, Sammlungen anlegen) kommt mit Stufe 5.
- [x] Echtzeit: SignalR-Hub (`/notifications/hub`, MessagePack über WebSocket) und der anonyme
      Hub für „Mit Gerät anmelden"; der Web-Tresor hört ebenfalls zu.
- [x] Push-Relay für die Handy-Apps (Bitwarden-Installation, US/EU), getestet gegen einen
      lokalen Fake-Relay. Einrichten im Admin-Portal: Stufe 3.
- Ab hier kann der eigene Tresor umziehen.

### Stufe 3 — Web-Tresor und Admin-Portal ausbauen (0.4, Beta)

Das Grundgerüst beider kam schon mit 0.1. Hier kommt dazu, was davon von späteren Stufen
abhängt oder erst mit mehr Nutzern wichtig wird:

- [x] Web-Tresor: Anhänge und Sends (mit Stufe 4); eine Ansicht fürs Handy (unter 760 px eine
      Ebene nach der anderen — Liste, Eintrag, Menü — mit Leiste unten, Dialoge über den ganzen
      Bildschirm); das Admin-Portal ebenso. Der Browsertest läuft zusätzlich mit 390×844.
- [x] Admin-Portal: Push-Relay einrichten und testen (Schlüssel bleibt auf dem Server), größte
      Datei, Passwortprüfung an/aus, Speicher pro Nutzer
- [x] Einladungen über Admins hinaus: „Nutzer dürfen einladen“, mit Kontingent pro Nutzer (offene
      Einladungen zählen mit), nie als Admin; im Tresor unter Einstellungen → Einladen
- [x] Statistik über die Zeit: eine Zeile pro Tag (`daily_stats`, stündlich geschrieben),
      Diagramme für Nutzer, Einträge, Dateien, Anmeldungen
- [x] Backups im laufenden Betrieb zurückspielen (Master-Passwort; SQLite-Backup-API in die
      laufende Datenbank, vorher ein Backup des jetzigen Stands; nur Backups dieses Servers)

### Stufe 4 — Alles, was Vaultwarden für Einzelne kann (0.4, Beta)

Vorgezogen vor Stufe 2 und 3, weil der Umzug von Vaultwarden Anhänge, Sends und Notfallzugriffe
mitbringen soll. Die Version heißt 0.4, nicht 1.0: 1.0 kommt nach dem Test auf echten Geräten.

- [x] Anhänge (hochladen, herunterladen per Link mit Token, bis 500 MB, im Admin-Portal
      änderbar), in Web-Tresor, offiziellen Clients und `bw`-CLI
- [x] Sends: Text und Datei, Passwort, Ablauf, Löschdatum, Zugriffszähler; öffentliche Seite im
      Web-Tresor; der neue `send_access`-Weg der Bitwarden-Clients ab 2026.6 und der alte
- [x] Notfallzugriff: einladen, annehmen, bestätigen (mit Fingerabdruck-Satz), anfragen,
      Wartezeit, freigeben/ablehnen, ansehen, übernehmen; Mails dazu
- [x] WebAuthn / FIDO2 als zweiter Faktor (eigene Prüfung mit `ring`, dazu die
      Connector-Seiten für Erweiterung und Apps), Anmeldung mit Passkey im Web-Tresor, mit PRF
      auch Entsperren
- [x] „Mit Gerät anmelden" (auch für Adressen ohne Konto gleich beantwortet), API-Key für die
      CLI
- [x] Passwortprüfung im Web-Tresor: schwach, mehrfach, ohne https, Datenlecks über den eigenen
      Server bei Have I Been Pwned (k-Anonymität, im Admin-Portal abschaltbar)

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

## Checkliste vor einem Release (Browsererweiterung und Apps)

Was CI nicht kann, von Hand gegen die Beta, mit dem Server als „selbst gehostet":

- Browsererweiterung (Firefox und Chrome): Anmelden, mit 2FA (App und Mail), Eintrag anlegen,
  Autofill auf einer Seite, Passwort-Generator, Sperren und Entsperren, Abmelden
- Android- und iOS-App: dasselbe, dazu Autofill im System und Entsperren mit Biometrie
- Desktop-App von Bitwarden: Anmelden, Sync, Eintrag anlegen
- UwULock: Anmelden, Sync, Eintrag bearbeiten
- Ein Eintrag, den eine App angelegt hat, öffnet sich im Web-Tresor und umgekehrt

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
- Web-Tresor und Admin-Portal schon in 0.1: der Web-Tresor an der Wurzel `/`, das Admin-Portal
  unter `/admin`, beide im Look der UwULock-App.
- Keine Bestätigung neuer Geräte per Mail (Bitwardens „new device verification"): wer mehr
  Schutz will, richtet 2FA ein. Eine Mail bei jeder Anmeldung eines neuen Geräts gibt es, im
  Admin-Portal abschaltbar.
- Anhänge auf der Platte; S3-artiger Speicher erst, wenn die Firma ihn braucht.
- AGPL-3.0, Registrierung nur per Einladung, Deutsch und Englisch.
