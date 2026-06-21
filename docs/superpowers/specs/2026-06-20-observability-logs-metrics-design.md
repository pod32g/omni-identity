# Observability: ship logs to omnilog + enrich metrics for omni-metrics

**Date:** 2026-06-20
**Status:** Approved (forks confirmed with user)
**Scope:** Two integrations for omni-identity, both off by default:

1. **Logs → omnilog** via an **in-app slog shipper**: a non-blocking handler that
   batches structured records and POSTs NDJSON to omnilog `POST /api/v1/ingest`
   (`X-Api-Key`), while still logging to stdout.
2. **Metrics → omni-metrics** via **scrape**: enrich omni-identity's existing
   `/metrics` with identity-meaningful series, and configure omni-metrics to
   scrape it.

## Environment (all on 192.168.68.34, separate compose networks → talk via host IP)

- omni-identity: host `:8081` → container `:8080`.
- omnilog: host `:8080`; ingest `POST /api/v1/ingest`, header `X-Api-Key`,
  NDJSON body (`service`/`level`/`message` + arbitrary searchable keys); keys via
  `OMNILOG_INGEST_KEYS`.
- omni-metrics: host `:9090`; configured with `-config <file>` containing
  `scrape_configs` (`job_name` + `static_configs.targets`), `metrics_path`
  default `/metrics`.

## 1. In-app log shipper (`internal/logship`)

New leaf package:

- `Config{Enabled, URL, APIKey, Service string; ...}` (batch/flush/buffer have
  internal defaults).
- `Handler` implements `slog.Handler`: `Handle` formats a record to a JSON object
  `{time, level (lowercased), service, message, <attrs...>}` and enqueues it to a
  buffered channel **non-blocking** (drop + count on overflow — logging must never
  block or fail a request). `WithAttrs`/`WithGroup` carry attrs.
- A background worker batches (size or interval) and POSTs NDJSON to
  `<URL>/api/v1/ingest` with `X-Api-Key` and a short timeout; on error retries a
  couple times then drops the batch. `Close(ctx)` flushes on shutdown.
- `Fanout(...slog.Handler) slog.Handler` tees records to multiple handlers so we
  keep stdout JSON **and** shipping.

`cmd/omni-identity` wires it: always build the stdout JSON handler; when
`cfg.Logging.Enabled`, also build the shipper and set the default logger to
`Fanout(stdout, shipper)`; flush via `Close` in the existing shutdown path.

Config (`internal/config`, `OMNI_LOGGING_*`):
```yaml
logging:
  enabled: false
  url: ""              # omnilog base, e.g. http://192.168.68.34:8080
  api_key: ""          # SECRET — config/env only
  service: omni-identity
```
Validation when enabled: `url` and `api_key` required.

## 2. Metrics enrichment (`internal/web`)

Extend the hand-rolled Prometheus exposition (no client lib, matching the current
style). Keep existing `omni_identity_http_requests_total` /
`..._by_status{status}`; add:

- `omni_identity_logins_total{source,result}` — source ∈ {local, ldap, unknown},
  result ∈ {success, failure}. Incremented at each outcome in `handleLoginSubmit`.
- `omni_identity_mfa_total{result}` — result ∈ {challenge, success, failure}.
- `omni_identity_tokens_issued_total{type}` — type ∈ {access, id, refresh}, in the
  token endpoint on success.
- `omni_identity_active_sessions` (gauge) — from a new store
  `CountActiveSessions(ctx)` (non-expired), read at render time.
- `omni_identity_build_info{version} 1` — version via `web.BuildVersion` set from
  `main` (default "dev").

The `metrics` type gains labeled counter maps (mutex-guarded) + increment helpers;
`render()` emits all series; `handleMetrics` appends the gauge from the store.

## 3. Receivers + deploy wiring (durable, like the LDAP work)

- **omni-identity** `docker-compose.yml`: add `OMNI_LOGGING_*` env (off-by-default,
  interpolated); real URL + API key in host `~/omni-identity/.env`. Commit the
  compose to the repo; push to main (CI deploys).
- **omnilog**: set `OMNILOG_INGEST_KEYS=<generated>` in `~/omnilog/.env` (compose
  already interpolates it) and restart. The same key goes in omni-identity's
  `.env` as `OMNI_LOGGING_API_KEY`. No omnilog code/repo change.
- **omni-metrics**: add a config file with a `omni-identity` scrape job
  (`targets: [192.168.68.34:8081]`) plus the existing self-scrape; mount it and
  add `-config` to the compose command. Commit to the omni-metrics repo (durable)
  and apply on host.

## 4. Verification

- Unit: config parse/validate/env; shipper ships NDJSON with the key to an
  httptest server, batches, and never blocks on overflow/failure; fanout tees;
  metrics `render()` includes the new series after increments.
- Live: after deploy, query omnilog (`/api/v1/search` or `query`) for
  `service=omni-identity` events; confirm omni-metrics shows the `omni-identity`
  target `up` and the new series present.

## Out of scope
- Shipping audit events (DB-backed) to omnilog — separate from the slog stream.
- Push-based metrics (`/api/v1/push`) — scrape is sufficient here.
- A shared docker network for name-based addressing — host IP is enough now.
