# certific

A single Go binary that shuttles Traefik's `acme.json` between a single-writer
"issuer" Traefik and many "gateway" Traefiks via S3. One image, one binary,
two run modes (`upload` and `download`) selected by the `--mode` flag.

## Problem

Traefik has no leader election for its ACME client. Running Traefik as a
global edge proxy — one replica per gateway node, each terminating TLS
locally — means every replica owns its own `acme.json` and runs its own
ACME flow against the upstream DNS-01 provider. When two replicas try to
issue a certificate for the same hostname at the same time, they race on
the `_acme-challenge.<host>` TXT record: one replica writes its nonce, the
other overwrites or cleans it up, and the ACME authority sees the wrong
value or no record at all. The result is intermittent issuance failures
and divergent local `acme.json` files across gateways.

The documented Traefik fix is "run exactly one instance that issues
certs," which conflicts with the global edge-proxy shape that lets every
gateway terminate TLS locally.

## Approach

Run one writer, treat S3 as the bus, keep every gateway as a reader —
but only ship cert material to the gateways, not the issuer's whole
ACME state.

- One issuer-side Traefik holds the DNS provider credentials and is the
  only process that can ever start an ACME flow. Its `acme.json` lives
  on a single node-local volume alongside `certific upload`.
- The same Traefik labels that already drive routing on the gateways drive
  issuance on the issuer, so adding a routed service doesn't require a
  parallel cert config.
- `certific upload` pushes the issuer's `acme.json` to S3 on every change.
- `certific download` on each gateway pulls `acme.json` from S3, parses
  it, and renders one `.crt` + `.key` per certificate plus a `tls.yml`
  index into a versioned snapshot under `<out-dir>/versions/<id>/`.
  After each successful render it atomically swaps `<out-dir>/current`
  (a symlink) to point at the new snapshot.
- Gateway Traefik runs with `--providers.file.directory=<out-dir>/current`
  and **no `certificatesResolvers` block at all**. It physically cannot
  start an ACME flow even if the directory is empty — a cache miss on a
  brand-new domain fails the TLS handshake on that one gateway until the
  next sync, which is bounded, visible, and self-healing rather than a
  silent race.

`certific` is the sidecar that does the shuttling. One image, one binary,
two modes:

```
certific upload   --path /etc/acme/acme.json --bucket … --key acme.json
certific download --out-dir /etc/certs       --bucket … --key acme.json --interval 60s
```

In `upload` mode it watches the local `acme.json` with `fsnotify`,
debounces bursts, and pushes changed contents to S3 (deduplicated by
sha256). On boot it first tries to seed the local file from S3 so the
issuer Traefik starts with a warm cache.

In `download` mode it polls S3 on `--interval`, `HEAD`s first so an
unchanged object never re-downloads, parses the fetched bytes into
per-domain PEM cert/key pairs, writes them to a new
`<out-dir>/versions/<id>/` snapshot alongside a `tls.yml` Traefik
dynamic config that lists them, then renames a sibling `current.new`
symlink onto `current`. Same-directory symlink rename is atomic on
POSIX filesystems, so the gateway Traefik never sees a half-applied
update. All output files are `chmod 0600` because they contain private
keys; older snapshots are pruned to `--keep` (default 2).

Both modes back off with jitter on transient S3 errors and keep running.
Downstream Traefiks keep serving the last good cert until S3 recovers.

## Quickstart

The shape below assumes:

- An S3 bucket (`example-acme`) with one object key (`acme.json`).
- Two scoped credential sets — one with `GetObject`+`PutObject` for the
  issuer side, one with `GetObject` only for the gateway side. Mount them
  however your platform mounts secrets (env vars, Docker secrets,
  Kubernetes secrets).
- An issuer-side Traefik pinned to a single node (so its acme volume is
  stable across reschedules) and a gateway-side Traefik running globally.
- A node label distinguishing the issuer node from the gateway nodes (the
  examples below use `role=issuer` and `role=gateway`).

### Docker Swarm

```sh
# Issuer side: one Traefik + one certific upload, pinned to the same node.
docker service create \
  --name traefik-issuer \
  --replicas 1 \
  --constraint 'node.labels.role==issuer' \
  --mount type=volume,source=acme-issuer,target=/etc/acme \
  --secret dns_api_key \
  traefik:v3.6

docker service create \
  --name certific-upload \
  --replicas 1 \
  --constraint 'node.labels.role==issuer' \
  --mount type=volume,source=acme-issuer,target=/etc/acme \
  --env AWS_ACCESS_KEY_ID=… \
  --env AWS_SECRET_ACCESS_KEY=… \
  --env CERTIFIC_REGION=us-east-1 \
  ghcr.io/<owner>/certific:latest \
  --mode upload \
  --path /etc/acme/acme.json \
  --bucket example-acme \
  --key acme.json

# Gateway side: one Traefik + one certific download per gateway node.
docker service create \
  --name traefik \
  --mode global \
  --constraint 'node.labels.role==gateway' \
  --publish published=443,target=443 \
  --publish published=80,target=80 \
  --mount type=volume,source=gateway-certs,target=/etc/certs \
  traefik:v3.6 \
  --providers.file.directory=/etc/certs/current \
  --providers.file.watch=true

docker service create \
  --name certific-download \
  --mode global \
  --constraint 'node.labels.role==gateway' \
  --mount type=volume,source=gateway-certs,target=/etc/certs \
  --env AWS_ACCESS_KEY_ID=… \
  --env AWS_SECRET_ACCESS_KEY=… \
  --env CERTIFIC_REGION=us-east-1 \
  ghcr.io/<owner>/certific:latest \
  --mode download \
  --out-dir /etc/certs \
  --bucket example-acme \
  --key acme.json \
  --interval 60s
```

The issuer-side `traefik` and `certific upload` share the `acme-issuer`
volume on the same node. The gateway-side `traefik` and `certific
download` share the per-node `gateway-certs` volume (one volume per
gateway node — they don't share state between gateways). Traefik's
file provider follows the `current` symlink and reloads when its
target changes.

A worked compose example lives at
[examples/swarm/compose.yml](examples/swarm/compose.yml) and covers the
full shape (networks, secrets, both Traefik configs).

## Configuration

All flags also read from a matching `CERTIFIC_*` environment variable.
Precedence is flag → env → default. Flags that don't apply to the chosen
mode are rejected on the command line; the equivalent env var is silently
ignored in that mode so the same `--env-file` can be shared between the
upload and download sidecars.

| Flag | Env | Modes | Default | Description |
| ---- | --- | ----- | ------- | ----------- |
| `--mode` | `CERTIFIC_MODE` | both | _required_ | `upload` or `download`. |
| `--path` | `CERTIFIC_PATH` | upload | _required_ | Local path to the issuer's `acme.json`. Rejected on download. |
| `--out-dir` | `CERTIFIC_OUT_DIR` | download | _required_ | Output directory; rendered snapshots land at `<out-dir>/versions/<id>/` and the active one is symlinked from `<out-dir>/current`. Point Traefik's file provider at `<out-dir>/current`. Rejected on upload. |
| `--keep` | `CERTIFIC_KEEP` | download | `2` | Number of past snapshots to retain after each render. |
| `--bucket` | `CERTIFIC_BUCKET` | both | _required_ | S3 bucket name. |
| `--key` | `CERTIFIC_KEY` | both | `acme.json` | S3 object key. |
| `--region` | `CERTIFIC_REGION` | both | _SDK default_ | S3 region. |
| `--endpoint` | `CERTIFIC_ENDPOINT` | both | _AWS_ | Endpoint URL for non-AWS S3-compatible stores (MinIO, Backblaze B2, etc.). |
| `--interval` | `CERTIFIC_INTERVAL` | download | `60s` | Poll interval. Must satisfy `10s ≤ x ≤ 1h`. Rejected on upload. |
| `--health-addr` | `CERTIFIC_HEALTH_ADDR` | both | _disabled_ | Listen address for `/healthz` and `/metrics` (e.g. `:8080`). Empty disables the server. |
| `--health-grace` | `CERTIFIC_HEALTH_GRACE` | upload | `24h` | Staleness window applied to `/healthz` in upload mode. Rejected on download (download uses `2×--interval`). |
| `--log-level` | `CERTIFIC_LOG_LEVEL` | both | `info` | One of `debug`, `info`, `warn`, `error`. Output is JSON via `log/slog`. |

AWS credentials are read by the standard AWS SDK chain
(`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`,
shared config files, IMDS, etc.) — `certific` doesn't take credential
flags.

Every env var ending in `_FILE` is resolved at startup: the file at
that path is read and its trimmed contents become the value of the
same name without the suffix (Docker/Swarm secret convention — same
as Postgres and Traefik images). Use this to feed AWS credentials from
mounted Swarm secrets:

```yaml
environment:
  - AWS_ACCESS_KEY_ID_FILE=/run/secrets/aws_access_key_id
  - AWS_SECRET_ACCESS_KEY_FILE=/run/secrets/aws_secret_access_key
secrets:
  - aws_access_key_id
  - aws_secret_access_key
```

A plain env var wins over the file form if both are set (handy for
local debugging). An unreadable `_FILE` path is fatal — failing loudly
beats falling through to anonymous SDK calls.

### Health endpoint

When `--health-addr` is set, the binary exposes:

- `GET /healthz` — `200` if the most recent successful S3 operation was
  within the freshness window, `503` otherwise. The window is
  `2×--interval` in download mode and `--health-grace` (default `24h`) in
  upload mode. Upload's window is generous on purpose: a healthy uploader
  with no cert renewals does no S3 work for days at a time.
- `GET /metrics` — a small plaintext payload with the last-sync timestamp,
  enough for `curl | grep`. This is not a Prometheus exposition; the full
  metric set is intentionally out of scope.

The endpoint is opt-in so the default deploy has no listening sockets at
all.

## Failure modes

- **S3 is unreachable.** Both sides back off with jitter and keep
  running. The issuer continues to issue certs into its local
  `acme.json`; uploads back-fill when S3 returns. Gateways keep serving
  whatever `acme.json` they last synced — valid until the cert expires.
  No user-visible impact unless the outage exceeds remaining cert
  validity. Alert externally on the last-sync timestamp from `/healthz`
  or `/metrics`.
- **Issuer reschedules to a new node.** New task pulls `acme.json` from
  S3 on boot via `certific upload`'s bootstrap fetch, then the issuer
  Traefik starts with that warm cache. No re-issuance unless certs are
  near expiry.
- **First-ever deploy (no `acme.json` in S3 yet).** Upload mode logs the
  `404` and proceeds with an empty local file; the issuer's first issued
  cert becomes the first S3 upload. Download mode tolerates the same
  `404` on its first cycle and retries on the next interval.
- **New domain added.** Issuer picks it up via its Traefik provider,
  runs the ACME flow, writes `acme.json`. The uploader debounces and
  pushes within ~500ms. Gateways pull on their next interval — so the
  first few seconds of traffic to a brand-new hostname will fail the
  TLS handshake on whichever gateway hasn't synced yet. This is
  intentional: failure on a new domain is bounded and visible; a silent
  race on every renewal is not.
- **Upload sidecar wedged.** The issuer keeps writing locally; S3 falls
  behind. New certs don't reach gateways. The upload-mode `/healthz`
  endpoint flips to `503` after `--health-grace`.
- **Download sidecar wedged on one gateway.** That gateway serves stale
  (but valid) certs until the cert is close to expiry. Its `/healthz`
  flips to `503` after `2×--interval`.
- **Truncated upload mid-write.** Mitigated by reading the file into
  memory first, deduping by sha256, and uploading the full body in one
  `PutObject`. Enabling S3 versioning on the bucket adds a cheap rollback
  path if a bad upload ever does land.
- **Corrupted local file on a gateway.** The next download cycle
  re-parses `acme.json`, renders a fresh snapshot dir, and swaps the
  `current` symlink — both unaffected by the contents of the previous
  snapshot. Deleting `<out-dir>/current` manually forces a re-render on
  the next interval.
- **`acme.json` parse error mid-flight.** The downloader logs the parse
  error and does not update `lastEtag`, so the next interval re-fetches
  and re-parses. The previous `current` snapshot keeps serving in the
  meantime; gateways never serve from a half-parsed file.

## Limitations

- **Single object, single bucket.** One `acme.json` per deployment.
  Multi-cluster cert sharing isn't modelled — each cluster runs its own
  bucket and its own issuer.
- **No app-level encryption.** `acme.json` is stored in S3 with whatever
  server-side encryption the bucket is configured for. The credentials
  the gateways hold are `GetObject`-only, but anyone with read access to
  the object has the private keys. Scope the IAM accordingly.
- **No leader election.** "One writer" is enforced by deploying exactly
  one upload-mode replica, not by coordination. Running two uploaders
  against the same bucket would re-introduce the upload race the design
  exists to prevent. Use whatever your scheduler offers (`replicas: 1`,
  a `StatefulSet`, a placement constraint) to keep the upload side
  singleton.
- **No Prometheus client.** `/metrics` is a curl-friendly placeholder,
  not a full exposition. If you need scraping today, alert on the
  `/healthz` status code.
- **fsnotify edge cases.** Upload mode watches the file with `fsnotify`,
  which on Linux handles `Write`/`Create` and the rename-then-create
  pattern Traefik uses. Other writers that swap the file out via a
  different syscall pattern may need testing.
