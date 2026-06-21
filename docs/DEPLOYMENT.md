# Deployment

This guide describes how to deploy Omni Identity from this repository. Docker
Compose is the recommended path because the provided compose file already sets
up persistence, container hardening, health checks, and environment-based
configuration.

## Requirements

- A host with Docker and the Docker Compose plugin.
- A stable DNS name for production, for example `identity.example.com`.
- HTTPS termination through a reverse proxy, load balancer, or ingress.
- Persistent storage for the database volume and backups.
- A high-entropy one-time setup token for the first administrator.

For local-only testing, you can use loopback HTTP. For production, use HTTPS and
keep secure cookies enabled.

## Quick Start With Docker Compose

Clone the repository on the deployment host:

```sh
git clone https://github.com/pod32g/omni-identity.git
cd omni-identity
cp .env.example .env
```

Edit `.env` before the first start:

```sh
OMNI_IDENTITY_BIND_ADDR=127.0.0.1
OMNI_IDENTITY_HOST_PORT=8081
OMNI_SERVER_PUBLIC_URL=https://identity.example.com
OMNI_COOKIES_SECURE=true
OMNI_SETUP_TOKEN=<generate-a-long-random-value>
```

Generate the setup token with a local secret generator, for example:

```sh
openssl rand -base64 32
```

Build and start the service:

```sh
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:8081/healthz
```

Open the configured public URL and complete the first-run setup wizard. If the
public URL is not loopback, the wizard requires the `OMNI_SETUP_TOKEN` value.
After the first administrator exists, setup disables itself.

## Public URL And HTTPS

`OMNI_SERVER_PUBLIC_URL` is the canonical external origin for the identity
provider. It is also the default OIDC issuer, so it must be stable before
clients are registered.

For production:

- Set `OMNI_SERVER_PUBLIC_URL=https://identity.example.com`.
- Keep `OMNI_COOKIES_SECURE=true`.
- Keep `OMNI_IDENTITY_BIND_ADDR=127.0.0.1` when a local reverse proxy forwards
  traffic to the container.
- Terminate HTTPS at the proxy and forward traffic to the published local port.

Example Caddy reverse proxy:

```caddyfile
identity.example.com {
	reverse_proxy 127.0.0.1:8081
}
```

Example nginx reverse proxy:

```nginx
server {
    listen 443 ssl http2;
    server_name identity.example.com;

    ssl_certificate /etc/letsencrypt/live/identity.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/identity.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

For short-lived private testing with direct HTTP on a non-loopback host, set all
of the following intentionally:

```sh
OMNI_IDENTITY_BIND_ADDR=0.0.0.0
OMNI_SERVER_PUBLIC_URL=http://your-test-host:8081
OMNI_ALLOW_INSECURE_HTTP=true
OMNI_COOKIES_SECURE=false
```

Do not use that configuration for production.

## Important Configuration

Runtime configuration is supplied through `.env` when using Docker Compose. The
full set of options is documented in [`.env.example`](../.env.example) and
[`config.example.yaml`](../config.example.yaml).

| Variable | Purpose |
|----------|---------|
| `OMNI_IDENTITY_BIND_ADDR` | Host interface for the published port. Use `127.0.0.1` behind a local reverse proxy. |
| `OMNI_IDENTITY_HOST_PORT` | Host port forwarded to the container's internal `8080`. |
| `OMNI_SERVER_PUBLIC_URL` | Canonical public base URL and default OIDC issuer. |
| `OMNI_SECURITY_ISSUER` | Optional issuer override. Leave empty unless it must differ from the public URL. |
| `OMNI_SETUP_TOKEN` | One-time bootstrap token required for first setup on non-loopback public URLs. |
| `OMNI_ALLOW_INSECURE_HTTP` | Explicit opt-in for non-loopback `http://` public URLs. |
| `OMNI_COOKIES_SECURE` | Enables Secure cookies. Required with HTTPS public URLs. |
| `OMNI_METRICS_TOKEN` | Enables `/metrics` when set; scrape with `Authorization: Bearer`. |

The `security`, `cookies`, `uploads`, and identity values are seeded from config
on first start and then become editable from Admin Settings. Listener,
database, setup token, metrics token, and HTTP server resource limits stay
config/env-controlled and require a restart to change.

## Persistent Data

The compose file stores application data in the `omni-identity-data` named
volume. This volume contains users, clients, sessions, signing keys, and the
SQLite database by default. Protect it like production credential material.

Inspect the volume:

```sh
docker volume inspect omni-identity-data
```

Back up the SQLite database while the service is running:

```sh
mkdir -p ./backups
docker compose exec omni-identity /omni-identity backup \
  --db /data/omni-identity.db \
  --out /tmp/omni-identity.db
docker cp omni-identity:/tmp/omni-identity.db ./backups/omni-identity-$(date +%Y%m%d%H%M%S).db
```

Check database integrity:

```sh
docker compose exec omni-identity /omni-identity integrity --db /data/omni-identity.db
```

## Upgrades

Back up the database before upgrading. Then update the source tree and recreate
the container:

```sh
git pull --ff-only
docker compose up -d --build
docker compose ps
curl -fsS http://127.0.0.1:8081/healthz
```

Database migrations run at application startup. Keep a recent backup before
running a new version.

## Metrics

`/metrics` is disabled by default. To enable it, set a strong token:

```sh
OMNI_METRICS_TOKEN=<long-random-token>
```

Scrape with:

```sh
curl -H "Authorization: Bearer $OMNI_METRICS_TOKEN" \
  https://identity.example.com/metrics
```

Keep metrics behind trusted monitoring infrastructure.

## Running Without Docker

You can also run the binary directly:

```sh
go build -o omni-identity ./cmd/omni-identity
./omni-identity serve -config config.yaml
```

Use [config.example.yaml](../config.example.yaml) as the starting point. The same
production rules apply: use HTTPS for the public URL, enable secure cookies, set
a setup token before first run, and keep the database and backups protected.

## Optional CI/CD

The repository includes a GitHub Actions workflow that builds and tests the
project. If you want automated deployment from your own fork, adapt the deploy
job to your infrastructure and provide a self-hosted runner or deployment
target with Docker Compose access.

Recommended deployment job shape:

1. Run tests and vulnerability checks on GitHub-hosted runners.
2. Deploy only from protected branches or tags.
3. Back up the database before recreating the container.
4. Run `docker compose up -d --build`.
5. Wait for `/healthz` and run `omni-identity integrity`.
6. Keep deployment secrets out of pull request jobs.
