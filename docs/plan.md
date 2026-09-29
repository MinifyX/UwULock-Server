# Plan: UwULock Server

Ein eigener, selbst gehosteter Server für [UwULock](https://github.com/MinifyX/UwULock-Client):
Bitwarden-kompatibel wie Vaultwarden, aber schneller, auf UwULock zugeschnitten, und mit Platz
für eigene Funktionen — ohne dass die offizielle Bitwarden-Browsererweiterung, die Apps oder die
CLI aufhören zu funktionieren.

Stand: September 2026. Stufe 0 ist fertig (0.0.1), Stufe 1 als 0.1-Beta — mit Web-Tresor und
Admin-Portal, die dafür aus Stufe 3 vorgezogen wurden. Stufen 2, 3 und 4 sind zusammen als
0.4.0-beta.1 erschienen, nach einem Sicherheitsreview
([docs/security-review-2026-09.md](security-review-2026-09.md)), dessen übrige (niedrige) Funde
0.4.0-beta.2 behebt; passend dazu UwULock 0.2.0-beta.3. Seitdem fertig: Stufe 4b (Betrieb und
Sicherheit), 4c (Tresor-Komfort), 4d (Familie) und Stufe 6 (UwU-Extras) — Stufe 6 kam vor Stufe 5.
Sie sind zusammen als 0.6.0-beta.1 erschienen, nach einem Sicherheitsreview
([docs/security-review-0.6.md](security-review-0.6.md)), dessen hohe und mittlere Funde behoben
sind; passend dazu UwULock 0.3.0-beta.1 mit Browsererweiterung. Die niedrigen Funde und Hinweise
dieses Reviews (SV-L1 bis SV-L41, SV-I1 bis SV-I4) behebt 0.6.0-beta.2. Stufe 5 (Firma) ist
zurückgestellt (Entscheidung von Lorin) und bleibt geplant.

Die Schnittstellen, die Server, Web-Tresor, UwULock-Client, Browsererweiterung, UwUSSH, UwURDP,
UwUMail und UwUAuth für 0.6 gemeinsam umsetzen, stehen in [uwu-api.md](uwu-api.md).

## Leitlinien

- **Zero-Knowledge wie bei Bitwarden.** Der Server sieht nie ein Passwort und nie einen Eintrag im
  Klartext, nur das, was die Clients verschlüsselt haben.
- **Die offiziellen Clients sind der Maßstab.** Browsererweiterung, Handy-Apps, Desktop-App und
  `bw`-CLI müssen immer funktionieren. Eigene Funktionen liegen deshalb unter `/uwu/v1/…`, wo die
  offiziellen Clients nie hinschauen.
- **Eine Datei, ein Container.** SQLite, ein Docker-Image, `install.sh` und `update.sh` wie bei
  UwUSync. PostgreSQL kommt später als zweites Backend hinter derselben Schicht.
- **Der Browser spricht nie mit Dritten.** Seit Stufe 4c holt der Server Website-Icons selbst und
  liefert sie unter `/icons/…` aus (abschaltbar); Web-Tresor und Apps fragen nur den eigenen
  Server.

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
      an. Verwalten (einladen, Sammlungen anlegen) kommt für Familien mit Stufe 4d, sonst mit
      Stufe 5.
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

### Stufe 4b — Betrieb und Sicherheit (vor Stufe 5; fertig, kommt mit 0.6)

Was ein Server für eine Familie oder ein kleines Büro braucht, bevor Firmen dazukommen. Kommt nach
den Tests auf echten Geräten.

- [x] Backups auf anderen Systemen, wie bei UwUMail Server (dort `docs/backups.md`): SFTP (z. B. ein
      NAS), S3 (MinIO, B2, Hetzner, Garage, …) oder ein eingehängter Ordner. Nächtlich und auf
      Knopfdruck, dedupliziert, standardmäßig verschlüsselt (Wiederherstellungsschlüssel einmal im
      Admin-Portal, später nach Passwort erneut), aufheben 7 Tage / 4 Wochen / 6 Monate (änderbar).
      Enthält Datenbank, Anhänge, Send-Dateien und die Schlüssel des Servers. Zurückspielen über die
      Kommandozeile auf einem neuen Server und im Admin-Portal wie die lokalen Backups; eine Warnung
      (Admin-Portal, Mail, Metrik), wenn das letzte gelungene Backup zu alt ist. Die lokalen Backups
      bleiben daneben. (Enthält auch die Dateien der Datei-Anfragen; `docs/backups.md`.)
- [x] Sicherheitshinweise für Nutzer, per Mail und als Liste im Web-Tresor (*Einstellungen →
      Sicherheit*, mit Gerät, IP und Zeit), in der Sprache des Kontos:
  - Fehlversuche: mehrere falsche Passwörter oder 2FA-Codes für das Konto
  - Konto-Änderungen: Master-Passwort, E-Mail, KDF, 2FA an oder aus, Schlüssel rotiert, API-Key
    erzeugt oder erneuert
  - Zugriffe: Notfallzugriff angefragt oder übernommen, „Mit Gerät anmelden"-Anfragen, Export
    des Tresors
  - Neues Gerät: die Mail gibt es schon, sie kommt mit in die Liste
  Mails werden gebündelt, damit ein Angriff nicht zur Mailflut wird; der Admin kann einzelne
  Arten abschalten. Das Ereignisprotokoll von Stufe 5 baut darauf auf.
- [x] Datei-Anfragen (Sends in umgekehrter Richtung): Ein Nutzer erstellt einen Link, über den
      jemand ohne Konto Dateien und Text zu ihm hochlädt, z. B. Ausweis-Scans. Verschlüsselt wird im
      Browser des Absenders mit dem öffentlichen Schlüssel des Kontos, der Server sieht nur
      Verschlüsseltes. Einstellbar: Ablauf, Anzahl und Größe der Dateien, Passwort, ein Hinweistext.
      Mail an den Nutzer, wenn etwas ankommt; ansehen und als Eintrag übernehmen in Web-Tresor und
      UwULock-Client (die offiziellen Clients kennen das nicht). Rate-Limits gegen Missbrauch; läuft
      auch unter den Send-Domains aus Stufe 6. (Server und Web-Tresor fertig, mit dem
      Extras-Schlüssel und `storagePerUserMb`; `docs/file-requests.md`. Die Seite unter `/r/<id>`
      läuft unter den Send-Domains aus Stufe 6. Die Live-Meldung an den
      Besitzer und das Zählen im Delta-Sync kommen mit dem Echtzeit-Kanal und dem Delta-Sync;
      die Seite im UwULock-Client mit dessen 0.3.)
- [x] UwUAuth als Anmeldung (OIDC; mit jedem anderen OIDC-Anbieter nutzbar):
  - Admin-Portal: Admins melden sich über UwUAuth an, auf Wunsch nur Mitglieder einer Gruppe
  - Tresor: „Mit SSO anmelden" in Erweiterung, Apps und Web-Tresor wie bei Vaultwarden (die
    SSO-Kennung der Clients ist egal); das Master-Passwort entsperrt den Tresor weiterhin, der
    Server sieht es nie
  - Konten: Wer in UwUAuth (in einer bestimmten Gruppe) ist, darf sich ohne Einladung
    registrieren und legt beim ersten Mal sein Master-Passwort fest; SCIM aus UwUAuth sperrt oder
    entfernt Konten
  - Suite-Kopplung per Code, sobald UwUAuth sie hat (dort Stufe 4), statt Client-ID und
    Adressen von Hand einzutragen
  Die Anmeldung per Einladung und Passwort bleibt daneben. (Fertig: Admin-Portal *Anmeldung*,
  Kopplung mit UwUAuth 0.4 oder von Hand, SCIM 2.0 unter `/scim/v2`, das Client-Geheimnis
  verschlüsselt unter `secret.key`; Admin-Recht per Gruppe oder UwUAuth-Rolle nur innerhalb der
  Admin-Netze, nie dem letzten Admin weggenommen; `docs/sso.md`. Getestet mit einem OIDC-Anbieter
  im Testprozess und im Browser; `bw login --sso` ist interaktiv und nicht automatisch getestet.)
- [x] Notfallblatt als PDF, im Browser erzeugt (der Server bekommt es nie): Server-Adresse und
      E-Mail als Text und QR-Code, ein leeres Feld für das Master-Passwort zum Eintragen von Hand, der
      2FA-Wiederherstellungscode (nach dem Master-Passwort) und eine kurze Anleitung für Angehörige,
      mit Hinweis auf eingerichtete Notfallzugriffe und ihre Wartezeit. Deutsch und Englisch.
      (Unter *Einstellungen → Notfallzugriff*; ein kleiner eigener PDF-Schreiber mit den
      Standardschriften, der QR-Code von `uqr` wie bei der Zwei-Schritt-Anmeldung.)
- [x] Monitoring:
  - [x] `/metrics` für Prometheus, wie bei UwUMail Server (dort `docs/metrics.md`): abschaltbar,
        mit Token oder nur auf einer eigenen Adresse; Anfragen und Latenzen, Anmeldungen (gelungen,
        fehlgeschlagen), Sync-Dauer, Live-Verbindungen, Push-Relay- und Mail-Fehler, Größe der
        Datenbank und der Dateien, Alter des letzten Backups, Ablauf des Zertifikats. Keine
        Adressen oder anderen Nutzerdaten als Labels. Dazu Beispiel-Alarmregeln.
  - [x] Logs an Grafana Loki, wie bei UwUMail Server: im Admin-Portal einschaltbar, gleiches JSON
        wie `log.format = json`, damit dieselben Abfragen für beide Wege gehen.
- [x] Admin-Benachrichtigungen zusätzlich zur Mail über ntfy, Gotify und Matrix: Backup
      fehlgeschlagen oder zu alt, Zertifikat läuft bald ab, Update verfügbar, viele Fehlversuche,
      Platte fast voll, Push-Relay oder Mailversand gestört. Pro Kanal wählbar, welche Ereignisse, mit
      Test-Knopf; Zugangsdaten bleiben auf dem Server.
- [x] Server-Richtlinien für alle Konten, im Admin-Portal (Stufe 5 bringt dazu die pro Organisation):
  - [x] 2FA-Pflicht, mit Frist: Danach lassen sich Konten ohne 2FA nur noch im Web-Tresor anmelden,
        um 2FA einzurichten; die Apps bekommen eine Meldung, was zu tun ist
  - [x] Mindest-KDF: Der Server sieht die KDF-Werte und lehnt schwächere ab; Konten darunter, etwa
        alte PBKDF2-Konten aus Vaultwarden, bekommen einen Sicherheitshinweis und im Web-Tresor
        einen Knopf zum Umstellen
  - [x] Stärke des Master-Passworts: kann nur der Client prüfen (der Server sieht das Passwort
        nie); der Web-Tresor tut es bei Registrierung und Änderung. Ob die offiziellen Clients eine
        serverweite Regel beachten, ist zu prüfen — bei Bitwarden hängen Richtlinien an
        Organisationen. Geprüft: ja, über `MasterPasswordPolicy` in der Antwort auf die Anmeldung.
- [x] Diagnose-Seite im Admin-Portal, auf Knopfdruck und nach jedem Update: Zertifikat und dessen
      Ablauf, Uhrzeit (2FA-Codes hängen daran), Mailversand, Push-Relay, Backup-Ziel, freier
      Speicher, und der Reverse-Proxy — kommen WebSockets durch, reicht das Upload-Limit für die
      größte erlaubte Datei, wird die echte Client-IP übergeben, stimmt die öffentliche Adresse. Pro
      Punkt, was zu tun ist (mit Beispielen für Caddy und nginx). Das Backup-Ziel außer Haus
      kommt mit den Backups auf anderen Systemen dazu.
- [x] Admin-Portal nur aus bestimmten Netzen (Liste von CIDR, z. B. LAN und VPN), ausgewertet mit der
      echten Client-IP (auch hinter einem Proxy); von anderswo antwortet `/admin` mit 404. Gilt auch
      für die Anmeldung per UwUAuth (mit ihr). Tresor, Sends und Kommandozeile sind davon nicht
      betroffen; `uwulock-server settings set adminNetworks '[]'` ist der Weg zurück.

### Stufe 4c — Tresor-Komfort (vor Stufe 5; fertig bis auf den Umzug von Bitwarden im Client, kommt mit 0.6)

Was Einzelnen und Familien im Alltag fehlt, bevor Firmen dazukommen. Kommt nach Stufe 4b.

- [x] Icons für Einträge:
  - Automatisch: Der Server holt das Icon der Website (`<link rel="icon">`,
    `apple-touch-icon`, `/favicon.ico`), rechnet es in PNG um und hebt es auf; Web-Tresor,
    UwULock-Client und die offiziellen Clients bekommen es über `/icons/<host>/icon.png`.
    Standardmäßig an, im Admin-Portal abschaltbar, Cache dort leerbar. Nur öffentliche Adressen:
    Der Server prüft jede aufgelöste IP (auch nach Weiterleitungen, gegen DNS-Rebinding), mit
    Zeit- und Größenlimits; die Website sieht nur die IP des Servers.
  - Lokale Adressen (private IPs, `.local`, `.lan`, Namen ohne Punkt): Der Server fragt nie ins
    interne Netz. Web-Tresor und UwULock-Client laden das Icon selbst vom Gerät im Heimnetz und
    speichern es als eigenes Icon. Im Browser verhindern Mixed Content (https-Tresor,
    http-Gerät) und CORS das oft; dann geht es im UwULock-Client oder von Hand.
  - Eigene Icons: hochladen (PNG, JPEG, WebP; SVG nur in PNG umgerechnet), im Client auf
    128 px verkleinert, mit dem Schlüssel des Kontos verschlüsselt unter `/uwu/v1` zur
    Eintrags-ID gespeichert. Sichtbar in Web-Tresor und UwULock-Client; die offiziellen Clients
    fragen Icons ohne Anmeldung nur pro Hostname ab und zeigen deshalb das automatische.
  - Icon-Bibliothek: [selfh.st Icons](https://selfh.st/icons/) und Dashboard Icons (Quelle und
    Lizenz im Tresor angeben). Der Server
    spiegelt nur den Index; die Suche läuft im Tresor darüber. Ein gewähltes Icon holt der Server
    bei Bedarf, hebt es auf und liefert es aus — der Browser spricht nie mit selfh.st oder einem
    CDN. Im Eintrag wird es wie ein eigenes Icon verschlüsselt gespeichert, damit der Server
    nicht erfährt, welches Icon zu welchem Eintrag gehört.
  - Reihenfolge: eigenes Icon, sonst automatisches (Host, dann Basis-Domain), sonst eines aus
    den mitgelieferten Icon-Datenbanken, sonst Standard-Symbol.
  - Icon-Datenbanken im Binary (fertig in 0.6.0-beta.2): 2FA Directory (MIT, Domain → Logo),
    Simple Icons (CC0; ohne Icons mit eigener `license` oder `guidelines`; Glyphe auf Kachel in
    Markenfarbe; Domains nur eindeutig über 2FA-Directory-Namen und die `source`-Domain) und
    Dashboard Icons (Apache-2.0; Geräte im Heimnetz nach Namen, Teil der Bibliothek). Feste
    Upstream-Commits in `crates/uwulock-server/icon-databases/sources.json`, Packs mit
    `SHA256SUMS`, erneuert mit `node scripts/icons/update.mjs --bump`; je Datenbank ein Schalter
    im Admin-Portal, Lizenzen in `THIRD-PARTY-NOTICES.txt` und `docs/icons.md`.
  - Hat eine Adresse kein eigenes Icon (Fehlerseite, 404, kein Link, kein `/favicon.ico`), nimmt
    der Server das der Domain darüber, bestimmt mit der eingebauten Public Suffix List
    (`account.example.com` → `example.com`); IPs, Namen ohne Punkt und Heimnetz-Namen bleiben.
    Landet die Seite einer Unteradresse nach Weiterleitungen auf einer fremden Website, zählt
    deren Icon nicht. (Fertig in 0.6.0-beta.2; der Cache beginnt neu unter `icons/auto-2`.)
  (Fertig: `/icons/<host>/icon.png` mit Prüfung jeder aufgelösten Adresse, fester Verbindung
  zur geprüften, Grenzen für Zeit, Größe und Bildgröße; eigene Icons verschlüsselt unter
  `/uwu/v1/icons/own`; die Bibliothek sind selfh.st Icons, CC BY 4.0, geprüft am 2026-09-28, und
  seit 0.6.0-beta.2 Dashboard Icons, Apache-2.0; `docs/icons.md`. Im UwULock-Client mit dessen 0.3.)
- [x] Import aus anderen Passwort-Managern im Web-Tresor, gelesen im Browser (der Server sieht nur
  Verschlüsseltes): KeePass/KeePassXC (KDBX mit dessen Passwort, und CSV), 1Password (1PUX und
  CSV), Chrome/Edge, Firefox, Apple Passwörter, Proton Pass, LastPass. Mit Vorschau, Ordnern und
  TOTP; was nicht passt, wird zur Notiz. Bitwardens eigene Importer dienen als Maßstab.
  (Fertig: KDBX 4 und 3.1 mit Passwort und Schlüsseldatei, Argon2d/Argon2id und AES-KDF in der
  WebAssembly, AES oder ChaCha20; unbekannte Felder werden eigene Felder, nichts fällt still weg;
  Anhänge nicht. Getestet mit kleinen erzeugten Dateien jedes Formats; `docs/import.md`.)
- [x] Reisemodus: Ordner lassen sich als „auf Reisen ausblenden" markieren. Ist der Modus an, lässt
  der Server deren Einträge (samt Anhängen) aus Sync und allen Abfragen weg; die Apps entfernen
  sie beim nächsten Sync auch lokal — das geht mit den offiziellen Clients. Einschalten auf jedem
  Gerät im Web-Tresor, ausschalten nur mit Master-Passwort und 2FA. Der Server kennt dafür nur
  die Ordner-IDs, nie ihre Namen.
  (Fertig, auch die Ordner selbst sind ausgeblendet; Leeren des Tresors und neue Schlüssel
  warten, solange er an ist; `docs/travel-mode.md`. Die Epoche des Delta-Syncs kommt mit Stufe 6.)
- [x] Versionen von Einträgen: Bei jeder Änderung hebt der Server den vorigen verschlüsselten Stand
  auf (Anzahl bzw. Tage im Admin-Portal einstellbar, zählt zum Speicher); zurückholen im
  Web-Tresor und UwULock-Client. Anhänge nicht. Beim Rotieren der Schlüssel werden die alten
  Stände im Client neu verschlüsselt oder verworfen (noch zu entscheiden); endgültig gelöschte
  Einträge verlieren auch ihre Versionen.
  (Fertig; entschieden: Web-Tresor und UwULock-Client verschlüsseln sie beim Rotieren über
  `POST /uwu/v1/accounts/rotate-keys` neu, rotiert ein offizieller Client, verwirft der Server
  die persönlichen.)
- [x] Erinnerung ans Erneuern eines Passworts, nur wenn man sie pro Eintrag einstellt (nach N Monaten
  oder an einem Datum). Der Server speichert nur Eintrags-ID und Datum und schickt dann eine Mail
  ohne Namen des Eintrags („Ein Eintrag in deinem Tresor ist fällig") mit Link in den
  Web-Tresor; dort und im UwULock-Client sind fällige Einträge markiert.
  (Fertig: Mail stündlich, Link `#/vault?due=1`, Glocke und Bereich *Fällig* im Web-Tresor.)
- [x] Bericht „2FA möglich, aber nicht eingerichtet" bei der Passwortprüfung: Einträge für Websites,
  die laut [2fa.directory](https://2fa.directory/) 2FA anbieten, bei denen aber kein TOTP
  hinterlegt ist, mit Link zur Anleitung der Website. Der Server spiegelt die Liste täglich
  (Lizenz prüfen), verglichen wird im Browser — der Server erfährt nicht, welche Websites im
  Tresor sind.
  (Fertig: `https://api.2fa.directory/v3/all.json`, MIT-Lizenz, geprüft am 2026-09-29, Quelle
  steht unter dem Bericht; der Server holt sie erst, wenn jemand fragt, dann täglich.
  `docs/sharing.md`.)
- [x] „Eintrag als Send teilen": Ein Knopf am Eintrag (Web-Tresor, UwULock-Client) macht daraus
  einen Text-Send; man wählt, welche Felder hinein sollen (Benutzername, Passwort, Notiz, eigene
  Felder, nie das TOTP-Geheimnis). Vorgaben: Ablauf nach einem Tag, einmal abrufbar, optional mit
  Passwort. Ein ganz normaler Send, also auch in den offiziellen Clients sichtbar.
  (Fertig im Web-Tresor, mit `uwulock-core::send::share_text` wie im UwULock-Client; auch nur für
  bestimmte Adressen.)
- [x] Sends nur für bestimmte E-Mail-Adressen, wie in den neueren Bitwarden-Clients: Wer den Link
  öffnet, gibt seine Adresse an und bekommt einen Code per Mail; erst dann gibt der Server den
  Send heraus (über den `send_access`-Weg, den es schon gibt). Der Server kennt dafür die
  Adressen. Braucht Mail; ohne Mail im Admin-Portal ist die Option aus.
  (Fertig: Bitwardens `authType`/`emails`, Code 5 Minuten und einmal, 5 falsche beenden ihn,
  höchstens eine Mail pro Minute und 5 pro Stunde je Send und Adresse; dieselbe Antwort für
  Adressen auf und nicht auf der Liste. Im Browser getestet mit einem Mailserver im Testskript.)
- [ ] Umzug von Bitwarden (Cloud und selbst gehostet): Bitwardens Export lässt Anhänge und
  Organisationen weg. Der UwULock-Client meldet sich an beiden Servern an und überträgt Einträge,
  Ordner, Anhänge und Sends (entschlüsselt nur im Client, neu verschlüsselt für UwULock);
  Organisationen, sobald sie hier angelegt werden können (Stufe 4d bzw. 5). Braucht ein
  Client-Release.
- [x] Barrierefreiheit im Web-Tresor und Admin-Portal: vollständig mit Tastatur bedienbar (mit
  Kürzeln und einer Übersicht dazu), mit Screenreader nutzbar, ein Modus mit hohem Kontrast; Ziel
  WCAG 2.2 AA, geprüft mit axe im bestehenden Browsertest, ohne ihn spürbar langsamer zu machen.
  (Fertig: Übersicht der Kürzel mit `?`, Listen mit Pfeiltasten, Sprung zum Inhalt, Live-Regionen
  für Meldungen, Kontrast „Hoch" (oder wie das System), axe-core 4.13 einmal pro Hauptseite in
  den Browsertests, schwere Funde lassen sie scheitern — zusammen etwa 3 s.
  `docs/accessibility.md`; mit einem echten Screenreader noch nicht ausprobiert.)
- [x] Eigenes Branding im Admin-Portal: Name, Logo (hell und dunkel), Akzentfarbe und Favicon für
  Web-Tresor, Anmeldung, Send- und Datei-Anfrage-Seiten und Mails; wie bei UwUMail Server (dort
  `docs/branding.md`). Die offiziellen Clients bleiben, wie sie sind. Mit den Send-Domains aus
  Stufe 6 auch pro Domain.
  (Fertig: Bilder werden als PNG neu gezeichnet, auch SVG; die Farbe braucht 3:1 zu Weiß und zum
  dunklen Hintergrund, die Töne daraus rechnet UwUMails Palette; gespeichert pro Bereich, damit
  Stufe 6 pro Send-Domain nur noch die Routen braucht. `docs/branding.md`. Pro Send-Domain seit
  Stufe 6, `docs/send-domains.md`.)

### Stufe 4d — Familie (vor Stufe 5; fertig, kommt mit 0.6)

Teilen in der Familie, ohne auf alles aus Stufe 5 zu warten: eine schlanke Organisation, wie
Bitwardens „Families".

- [x] Eine Familie anlegen im Web-Tresor (der Admin legt fest, wer das darf, wie viele Mitglieder
      eine Familie höchstens hat und wie viele ein Konto besitzen darf); Rollen nur Eigentümer
      und Mitglied. Der Schlüssel der Familie wird im Browser gemacht und für den öffentlichen
      Schlüssel des Eigentümers verpackt, wie bei Bitwardens Clients.
- [x] Mitglieder einladen: Konten dieses Servers direkt (per Mail-Link oder im eigenen Tresor
      annehmen), neue Leute über die bestehenden Einladungsregeln (die Einladung in die Familie
      ist dann zugleich die auf den Server und zählt für das Kontingent); bestätigen mit dem
      Fingerabdruck-Satz, damit der Schlüssel der Familie beim Richtigen landet. Entfernen,
      verlassen, übergeben (ein weiterer Eigentümer), löschen; Mails auf Deutsch und Englisch,
      Sicherheitshinweise, Live-Updates an die Clients.
- [x] Sammlungen anlegen, umbenennen, löschen, mit Lese- oder Schreibrecht pro Mitglied; Einträge
      hinein verschieben aus Web-Tresor, UwULock-Client und den offiziellen Clients (die Verwaltung
      selbst nur im Web-Tresor, wie bei Bitwarden). Getestet mit zwei Konten und der Krypto des
      UwULock-Clients sowie im Browser und mit Bitwardens CLI (`bw create item` in eine Sammlung,
      `bw move`).
- [x] Aus Vaultwarden übernommene Organisationen lassen sich damit verwalten, soweit sie nur
      Eigentümer und Mitglieder brauchen.
- Gruppen, Richtlinien, Account-Recovery, Ereignisprotokoll und alles Weitere bleiben in Stufe 5,
  die darauf aufbaut.

### Stufe 5 — Firma (zurückgestellt, nach Stufe 6)

- Organisationen, Sammlungen, Rollen, Einladungen (aufbauend auf Stufe 4d)
- Gruppen, Richtlinien (2FA-Pflicht, Master-Passwort-Anforderungen, Account-Recovery)
- Ereignisprotokoll / Audit (auf den Sicherheitshinweisen aus Stufe 4b)
- PostgreSQL
- SSO mit Entra ID (OIDC an sich kommt mit Stufe 4b), Bitwarden Directory Connector (LDAP, Entra)
- Secrets Manager, kompatibel zu Bitwarden: Projekte, Secrets, Maschinen-Konten mit
  Zugriffstokens, für `bws`, Bitwardens SDKs, die GitHub Action und den Kubernetes-Operator — damit
  Docker Compose, CI oder Ansible ihre Zugangsdaten aus dem Tresor holen. Verschlüsselt wie bei
  Bitwarden (der Schlüssel steckt im Token, der Server sieht keine Secrets); Verwaltung im
  Web-Tresor. Vaultwarden kann das nicht. Hängt an Organisationen, darum hier.

### Stufe 6 — UwU-Extras (unter `/uwu/v1`, angekündigt unter `GET /uwu/v1/info`; vor Stufe 5 fertig, kommt mit 0.6)

- [x] Schlanker Echtzeit-Kanal und Delta-Sync für den UwULock-Client (`/uwu/v1/realtime`,
  `/uwu/v1/sync` mit Zählern, Tombstones 90 Tage und Epochen; `docs/sync.md`, Zahlen in
  `docs/performance.md`)
- [x] Suite-Tresor: eigene verschlüsselte Objekte für SSH-Hosts, RDP-Verbindungen, UwUMail-Konten —
  bewusst nicht in Bitwardens Eintragsliste, weil unbekannte Typen die offiziellen Clients
  stören könnten (Bereiche `ssh`/`rdp`/`mail`/`generic`, Suite-Anmeldung, `docs/suite.md`)
- [x] UwUSync ersetzen: UwUSSH und UwURDP synchronisieren über UwULock Server, mit Übernahme aus der
  UwUSync-Datenbank (die Übernahme machen die Apps selbst, die Datensätze sind nur dort lesbar;
  ihre Abläufe laufen in `uwulock-e2e`)
- [x] Passwort-Gesundheit: Der Client rechnet (der Server kennt keine Passwörter); der Server bietet
  einen HIBP-Proxy mit k-Anonymität und hebt den Bericht verschlüsselt auf (der Web-Tresor
  speichert und lädt ihn unter dem Extras-Schlüssel)
- [x] Eigene Domains für Sends: Im Admin-Portal lassen sich weitere Domains oder Subdomains
  (z. B. `send.example.com` neben `lock.example.com`) anlegen, unter denen nur Sends erreichbar
  sind — die Send-Seite und `/api/sends/access…`, kein Tresor, keine Anmeldung, kein
  Admin-Portal. Links werden kürzer, etwa `https://send.example.com/<access id>#<schlüssel>`;
  der Schlüssel bleibt hinter dem `#`, sonst sähe ihn der Server. Alte Links unter
  `/#/send/…` gehen weiter. Entschieden:
  - Die offiziellen Bitwarden-Clients bauen den Link selbst aus ihrer Web-Tresor-Adresse; die
    eigene Domain nutzen also nur Web-Tresor und UwULock-Client (dort über `/uwu/v1/info`).
  - Mehrere Send-Domains, vom Admin verwaltet; wählbar pro Send (und pro Datei-Anfrage), mit
    einem Standard pro Konto, den auch Sends aus den offiziellen Clients bekommen. Jeder Send
    ist unter der Hauptadresse und allen Send-Domains erreichbar; die Wahl bestimmt nur den
    Link und die Optik, darum verliert das Löschen einer Domain nichts außer ihren Links.
  - TLS pro Domain wählbar: Let's Encrypt über den Server selbst (TLS-ALPN-01 wie die
    Hauptadresse, je Name ein Zertifikat, per SNI ausgeliefert; auch neben Zertifikat-Dateien)
    oder ein Proxy davor.
  - Eigene Optik pro Domain (Name, Farbe, Logos, Favicon), sonst die des Servers; auch die
    Mail mit dem Code eines Sends für bestimmte Adressen kommt in der Optik der Domain.
  (Fertig: Admin-Portal mit Prüfung von DNS, HTTPS und Weiterleitung, Zertifikatsstand und
  Optik je Domain; Diagnose und Metrik je Domain; Web-Tresor mit Wahl am Send, an der
  Datei-Anfrage und dem Standard in den Einstellungen. `docs/send-domains.md`.)
- [x] Masken-Adressen von UwUMail: UwULock Server legt für ein Konto Masken-Adressen bei UwUMail
  Server an (dessen JMAP `MaskedEmail`, siehe `docs/jmap-masked-email.md` dort).
  (Fertig im Server und Web-Tresor, gegen einen nachgebauten UwUMail getestet — OAuth mit
  Registrierung, PKCE, Rotation der Refresh-Tokens, neue Registrierung bei `invalid_client`,
  429 — und im Browsertest; die Probe gegen einen echten UwUMail mit dem Scope `maskedemail`
  (UwUMail-Server PR #21) ist ein `#[ignore]`-Test zum Starten von Hand.
  `docs/masked-addresses.md`.)
  - Verbinden: Der Admin trägt im Admin-Portal die erlaubten UwUMail-Server ein; nur an diese
    schickt der Lock-Server Anfragen. Der Nutzer klickt im Web-Tresor „Mit UwUMail verbinden",
    meldet sich per OAuth (PKCE, dynamische Registrierung, beides hat UwUMail schon) bei
    UwUMail an und stimmt zu; die Verbindung steht dann in UwUMail unter *Sicherheit* und lässt
    sich dort und im Tresor trennen.
  - Das Refresh-Token liegt verschlüsselt auf dem Lock-Server (nicht im Tresor), damit auch die
    offiziellen Clients Adressen anlegen können. Braucht in UwUMail einen eigenen OAuth-Scope
    nur für Masken-Adressen — `mail` öffnet heute das ganze Postfach.
  - Anlegen im Web-Tresor (Generator und neben dem Benutzernamen im Eintrag), im UwULock-Client
    (über `/uwu/v1`, Client-Release nötig) und in den offiziellen Bitwarden-Clients: Der
    Lock-Server bietet eine addy.io- oder SimpleLogin-kompatible Schnittstelle, die man im
    Generator unter „Weitergeleitete E-Mail-Adresse" als selbst gehosteten Dienst einträgt, mit
    einem eigenen API-Key aus dem Web-Tresor (Fastmail geht nicht, dort ist die Adresse fest).
  - Domain: UwUMails Standard; in Web-Tresor und UwULock-Client aus den erlaubten Domains
    wählbar, die offiziellen Clients bekommen den Standard (bei addy.io vielleicht auch das
    Domain-Feld). `forDomain` ist die Seite des Eintrags, `url` der Link zum Eintrag.
  - Verwalten: eigene Seite im Web-Tresor mit Status, letzter Mail und zugehörigem Eintrag;
    an, aus, löschen. Am Eintrag ein Hinweis auf seine Masken-Adresse.
  - Wird ein Eintrag gelöscht, fragt der Web-Tresor, ob die Adresse abgeschaltet werden soll
    (Standard: ja, `disabled` — nicht gelöscht).
- [x] Funktionsschalter (0.6.0-beta.2, `docs/features.md`): Jedes Extra ist im Admin-Portal unter
  „Funktionen" an- und abschaltbar, gruppiert (Teilen, Im Tresor, Anmeldung, Betrieb, UwU-Apps),
  16 Schalter. Aus heißt: 404 `feature_off`, Hintergrundjobs ruhen, Web-Tresor und Admin-Portal
  blenden es aus, `/uwu/v1/info` meldet es unter `switches`; gelöscht wird nichts. Der Tresor
  und alles, was die Bitwarden-Apps nutzen, bleibt immer an; Website-Icons und HIBP behalten
  ihre eigenen Einstellungen. Neue Server starten nur mit Tresor und Icons
  (`UWULOCK_FEATURES`), aktualisierte behalten an, was benutzt wird (Migration 0017).
  Admin-API `GET|PUT /uwu/v1/admin/features`, auf der Kommandozeile `uwulock-server features`.

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

- Stufe 4b (Betrieb und Sicherheit), 4c (Tresor-Komfort) und 4d (Familie) vor Stufe 5 (Firma)
  vor Stufe 6 (UwU-Extras); 5 und 6 lassen sich tauschen.
- Web-Tresor und Admin-Portal schon in 0.1: der Web-Tresor an der Wurzel `/`, das Admin-Portal
  unter `/admin`, beide im Look der UwULock-App.
- Keine Bestätigung neuer Geräte per Mail (Bitwardens „new device verification"): wer mehr
  Schutz will, richtet 2FA ein. Eine Mail bei jeder Anmeldung eines neuen Geräts gibt es, im
  Admin-Portal abschaltbar.
- Anhänge auf der Platte; S3-artiger Speicher erst, wenn die Firma ihn braucht.
- AGPL-3.0, Registrierung nur per Einladung, Deutsch und Englisch.
- Extras sind abschaltbar, der Bitwarden-Standard nicht: Ein neuer Server bietet nur den Tresor
  und Icons, der Admin schaltet dazu, was er braucht. Abschalten löscht nie Daten.
