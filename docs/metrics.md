# Prometheus metrics

For people who run a monitoring system anyway, the server answers `GET /metrics` in the
[Prometheus text format](https://prometheus.io/docs/instrumenting/exposition_formats/): requests
and how long they took, logins, syncs, live connections, mail and push relay errors, how large
the database and the files are, when the last backup was written and when the certificate runs
out. No label ever names a person, an address, a host or an id.

It is off until an admin switches it on, and then it never answers everyone.

## Switching it on

Admin portal → *Monitoring* → *Prometheus metrics*. There are two ways to keep the metrics to
yourself:

- **With a token**, on the server's public address. *Make a token* creates 32 random characters
  in the browser; copy it before saving. The server keeps only its SHA-256 and never shows it
  again. A scraper sends it as `Authorization: Bearer <token>`; the server compares it in constant
  time and answers a wrong one with `401`. A network that keeps guessing gets `429`, like any
  other anonymous request that comes too often.
- **On an address of its own**, like `127.0.0.1:9100` or, in a container, `0.0.0.0:9100` with the
  port published only where the scraper is. There `/metrics` answers without a token, and the
  public address answers `404` as if there were no metrics.

The server refuses to switch the metrics on with neither. The same settings from a shell on the
box:

```bash
docker compose exec uwulock uwulock-server settings set metrics.listen '"0.0.0.0:9100"'
docker compose exec uwulock uwulock-server settings set metrics.enabled true
printf '%s' "$TOKEN" | docker compose exec -T uwulock uwulock-server settings set metrics.token -
docker compose restart uwulock
```

For an address of its own in a container, publish its port in `compose.override.yaml` next to
`compose.yaml` (update.sh leaves that file alone):

```yaml
services:
  uwulock:
    ports:
      - "127.0.0.1:9100:9100"
```

A change of `metrics.listen` in the portal takes effect at once: the server stops listening on the
old address and starts on the new one.

## Scraping

```yaml
scrape_configs:
  - job_name: uwulock
    scheme: https
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials: a-long-random-token-from-the-portal
    static_configs:
      - targets: ["lock.example.com"]
```

Or, on an address of its own, `scheme: http` and `targets: ["192.0.2.10:9100"]` without the
`authorization`. Every scrape reads a handful of numbers from the database; every 30 seconds to a
few minutes is plenty. Answers are never cached.

## What there is

| Metric | Type | Labels | What it is |
| --- | --- | --- | --- |
| `uwulock_build_info` | gauge | `version` | Always 1; the version that runs |
| `uwulock_http_requests_total` | counter | `route`, `method`, `status` | Requests answered. `route` is the route's template, like `/api/ciphers/{id}`; the web vault's files and unknown paths are `other`. `method` is one of the standard HTTP methods, anything else `other` |
| `uwulock_http_request_duration_seconds` | histogram | `route`, `method` | How long they took to answer |
| `uwulock_logins_total` | counter | `grant`: `password`, `refresh_token`, `client_credentials`, `webauthn`, `send_access`; `result`: `success`, `failure`, `two_factor` | Logins. `two_factor` is the answer that asks for the second step |
| `uwulock_sync_duration_seconds` | histogram | `kind`: `bitwarden`, `full`, `delta` | How long a sync took: of the official clients (`/api/sync`), and of UwULock's own clients, whole or as a delta ([sync.md](sync.md)) |
| `uwulock_live_connections` | gauge | `channel`: `signalr`, `anonymous`, `realtime` | Open live-update connections: of logged-in devices, of devices that wait for a "log in with a device" answer, and on UwULock's realtime channel |
| `uwulock_push_relay_errors_total` | counter | | Requests Bitwarden's push relay did not take |
| `uwulock_mail_sent_total`, `uwulock_mail_errors_total` | counter | | Mails that went out, and those the mail server did not take |
| `uwulock_database_bytes` | gauge | | The database, with its write-ahead log |
| `uwulock_files_bytes` | gauge | `kind`: `attachments`, `sends`, `file_requests` | Stored files |
| `uwulock_accounts`, `uwulock_items` | gauge | | Accounts; items, those in the trash included |
| `uwulock_backup_last_success_timestamp_seconds` | gauge | `target`: `local`, `offsite` | When the newest backup was written; `offsite` once one to another system worked ([backups.md](backups.md)) |
| `uwulock_certificate_expiry_timestamp_seconds` | gauge | `domain`: `main` | When the certificate clients see runs out: the server's own, or the proxy's in front of it. Looked at every six hours |
| `uwulock_loki_dropped_total` | counter | | Log lines dropped because Loki was away too long or refused them |
| `process_*` | | | The usual: CPU seconds, resident and virtual memory, open and allowed file descriptors, start time |

Counters start at 0 with every start of the server, which `rate()` and `increase()` understand.
Later versions add the send domains' certificates and the icon fetches.

## Alert rules to start with

```yaml
groups:
  - name: uwulock
    rules:
      - alert: UwULockBackupOld
        expr: time() - uwulock_backup_last_success_timestamp_seconds{target="local"} > 2 * 86400
        for: 1h
        annotations:
          summary: The newest backup of UwULock Server is older than two days.
      - alert: UwULockOffsiteBackupOld
        expr: time() - uwulock_backup_last_success_timestamp_seconds{target="offsite"} > 2 * 86400
        for: 1h
        annotations:
          summary: The last backup of UwULock Server on another system is older than two days.
      - alert: UwULockCertificateExpiring
        expr: uwulock_certificate_expiry_timestamp_seconds - time() < 14 * 86400
        annotations:
          summary: The certificate of UwULock Server runs out within 14 days.
      - alert: UwULockErrors
        expr: |
          sum(rate(uwulock_http_requests_total{status=~"5.."}[10m]))
            / sum(rate(uwulock_http_requests_total[10m])) > 0.05
        for: 10m
        annotations:
          summary: More than 5 % of the requests to UwULock Server fail on the server's side.
      - alert: UwULockFailedLogins
        expr: sum(increase(uwulock_logins_total{result="failure"}[15m])) > 50
        annotations:
          summary: Many failed logins at UwULock Server — somebody may be guessing.
      - alert: UwULockMailFailing
        expr: increase(uwulock_mail_errors_total[30m]) > 0 and increase(uwulock_mail_sent_total[30m]) == 0
        annotations:
          summary: UwULock Server cannot send mail.
      - alert: UwULockDown
        expr: up{job="uwulock"} == 0
        for: 5m
```

The server also tells its admins itself — by mail, ntfy, Gotify or Matrix — when backups fail,
the certificate runs out or the disk fills up: [notifications.md](notifications.md). Prometheus is
for when you want everything in one place.
