# Deployment

Omni Identity deploys to **192.168.68.34** via a **self-hosted GitHub Actions
runner on that same host** — mirroring the omni-logging pipeline. The runner
builds the image and runs `docker compose` locally on the target.

## Pipeline overview

[`.github/workflows/cicd.yml`](../.github/workflows/cicd.yml):

- **build** (every branch / same-repo PR): `docker compose build` — a gate that
  also runs `go test ./...` and `govulncheck` inside the image build. Fork PRs
  are never run on the self-hosted runner.
- **deploy** (`main` only): on the target host it
  1. backs up the live DB first (`omni-identity backup`, online `VACUUM INTO`),
     copying the snapshot to `~/omni-identity/backups`;
  2. stop-first recreates the container (`docker compose up --build -d`);
  3. waits for readiness via the in-container `healthcheck` subcommand;
  4. smoke-tests the published port (`http://localhost:8081/healthz`);
  5. runs `integrity` and **auto-heals from the latest backup** if it fails;
  6. retains the 10 most recent backups.

Deploys are serialized (`concurrency: deploy-omni-identity`) and never overlap.

## One-time prerequisite: register a runner for this repo

The existing `omnilog-34` runner is **scoped to the omni-logging repo** and
cannot be shared (personal-account runners are per-repo). Register a **second
runner instance** for omni-identity on the same machine. It must carry the
label **`omni-identity`** (matched by the workflow's `runs-on`).

On 192.168.68.34:

```sh
# 1. Get a registration token (valid ~1h). From your workstation:
#    gh api -X POST repos/pod32g/omni-identity/actions/runners/registration-token --jq .token
#    ...or copy the command shown in: GitHub → omni-identity → Settings → Actions → Runners → New self-hosted runner

# 2. On the host, in a NEW directory (do not reuse the omnilog runner dir):
mkdir -p ~/actions-runner-omni-identity && cd ~/actions-runner-omni-identity

# Reuse the same runner version already installed for omni-logging, e.g.:
RUNNER_VERSION=2.XXX.X   # match the existing omnilog runner
curl -o actions-runner.tar.gz -L \
  "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
tar xzf actions-runner.tar.gz

# 3. Configure against THIS repo with the omni-identity label:
./config.sh \
  --url https://github.com/pod32g/omni-identity \
  --token <REGISTRATION_TOKEN> \
  --labels omni-identity \
  --name omni-identity-34 \
  --unattended

# 4. Install + start as a service:
sudo ./svc.sh install
sudo ./svc.sh start
```

The runner's user needs the same tooling the omnilog runner already has on this
box: Docker + the compose plugin, plus `rsync` and `curl`, and membership in the
`docker` group.

## Configuration

Runtime config is provided via environment variables (no config file needed in
the container — see [`docker-compose.yml`](../docker-compose.yml)). Copy
[`.env.example`](../.env.example) to `.env` next to the compose file on the host:

| Variable | Default | Notes |
|----------|---------|-------|
| `OMNI_IDENTITY_HOST_PORT` | `8081` | Published host port (omni-logging owns 8080). |
| `OMNI_SERVER_PUBLIC_URL` | `http://192.168.68.34:8081` | Public base URL **and** OIDC issuer; must be stable. |
| `OMNI_SECURITY_ISSUER` | _(empty)_ | Defaults to the public URL. |
| `OMNI_COOKIES_SECURE` | `false` | Set `true` behind an HTTPS-terminating proxy. |

Persistent state (users, clients, sessions, signing keys) lives in the
`omni-identity-data` named volume and survives container recreation.

> Production note: serve over HTTPS with a real hostname and set
> `OMNI_COOKIES_SECURE=true`. The plain-http IP issuer is fine for a private LAN.

## First deploy

1. Register the runner (above).
2. Create `~/omni-identity/.env` on the host (or let the workflow rsync your
   committed defaults and rely on compose env defaults).
3. Push to `main` — the build gate runs, then the deploy creates the container.
4. Browse to `http://192.168.68.34:8081/` and complete the first-run admin wizard.

## Coexistence with omni-logging

Both stacks run on the same host without conflict: distinct compose project dirs
(`~/omnilog` vs `~/omni-identity`), container names, named volumes, and host
ports (8080 vs 8081).
