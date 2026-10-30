# UwULock-Server

Bitwarden-kompatibler Passwortserver (Rust/axum, SQLite) mit eigenem Web-Tresor (`web/`, Vite/React + Rust-WASM).

## Layout
- `crates/uwulock-store`: SQLite-Zugriff, Migrationen in `crates/uwulock-store/migrations/sqlite/`
- `crates/uwulock-api`: HTTP-Handler (Auth, Ciphers, Sends, Familien, SSO, WebAuthn, Admin …)
- `crates/uwulock-web`: bettet `web/dist` per `build.rs` ein (oder `UWULOCK_WEB_DIST`)
- `crates/uwulock-mail`, `-notify`, `-backup`: Mail, Benachrichtigungen, Backups
- `crates/uwulock-server`: Binary/Startup; `-bench`: Benchmarks (`bench.yml`); `-e2e`: E2E-Hilfscrate
- `web/`: Web-Tresor; `web/wasm`: eigenes Rust-Crate (eigene `Cargo.lock`, nicht im Workspace)
- `scripts/e2e/`: Node/Playwright-Browsertests, `bw-*.sh` mit Bitwarden-CLI; `docs/`: Feature- und Betriebsdoku

## Befehle
- Tests: `scripts/test.sh` (ruhig, Logs in `target/test-logs/`); `scripts/test.sh -p <crate> [filter]`; `CARGO_BUILD_JOBS` setzen
- Vor dem Commit: `scripts/test.sh --all` (fmt, clippy, wasm, web format/lint/types/tests; braucht `pnpm install` in `web/`)
- Web: `cd web && pnpm lint` (inkl. `scripts/check-i18n.mjs`, neue Strings in allen Sprachen) · `pnpm typecheck` · `pnpm test`
- WASM neu bauen: `cd web && pnpm wasm` (erzeugt `web/src/wasm/pkg`, gitignored)
- Browser-E2E: `scripts/e2e/local.sh <web|operations|family|…>` (HTTPS mit Test-CA, Playwright nur per Docker)
- Allgemeine Rust/pnpm-CI-Befehle: siehe ~/Projects/CLAUDE.md

## Fallen
- Bestehende Migrationen (`0001`–`0028`) nie ändern; neue fortlaufend nummeriert anlegen.
- `web/dist` und `web/src/wasm/pkg` sind generiert, nie von Hand bearbeiten; `pnpm build` nie parallel zu `cargo test`.
- `web/wasm` hat eigene `Cargo.lock` und eigenen Test: `cargo test --manifest-path web/wasm/Cargo.toml`.
- Neue UI-Texte in `web/src` ohne i18n-Eintrag lassen `pnpm lint` scheitern.

## Plan/Stand
- Einstieg: `docs/plan.md` (Stand, Entscheidungen), `CHANGELOG.md`, bei Bedarf `docs/<feature>.md`
- Reviews: `docs/security-review-*.md`

## Release
- Versionsbump in `Cargo.toml` und `## <version>` in `CHANGELOG.md` (CI übernimmt den Abschnitt ins GitHub-Release), Tag `vX` auf Merge-Commit
- Betroffene Assets: `install.sh`, `update.sh`, `compose.yaml`, `docker/`

## Security
- Kritische Bereiche: `crates/uwulock-api` (Auth, Ciphers, Sends, SSO, WebAuthn, Familien/Orgs, Anhänge), `crates/uwulock-store`, `crates/uwulock-backup`, `web/wasm` (Krypto im Client), TLS/ACME in `crates/uwulock-server`
- Vor jedem Feature-Release den globalen Subagent `security-reviewer` über den Bereich seit dem letzten Tag laufen lassen; Ergebnis nach `docs/security-review-<version>.md`
