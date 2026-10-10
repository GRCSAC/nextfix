# Installing NextFix

Three ways to run NextFix, from the simplest up:

| | Good for | What you need |
|---|---|---|
| **Executable** | one machine, the CLI in CI, a laptop running the dashboards | nothing: one file per platform |
| **Docker image** | a server the team shares, image scans, a reverse proxy in front | Docker (or any OCI runtime) |
| **From source** | development; see `README.md` "Run it" | Node 24+ and `npm install` |

All three are the same program: `nextfix scan …` prints decisions, `nextfix serve …` runs the
dashboards, `nextfix user …` manages accounts without the dashboard. `nextfix-server serve`
in older notes means `nextfix serve`.

## The executable

Each release on GitHub ships one file per platform, plus `SHA256SUMS`:

| File | Platform |
|---|---|
| `nextfix-<version>-linux-x64` | Linux, x86-64 |
| `nextfix-<version>-linux-arm64` | Linux, ARM 64 (Graviton, Raspberry Pi 4/5, Ampere) |
| `nextfix-<version>-win32-x64.exe` | Windows 10/11, x86-64 |
| `nextfix-<version>-darwin-arm64` | macOS, Apple silicon |
| `nextfix-<version>-darwin-x64` | macOS, Intel |

The file contains Node, NextFix, the dashboards and the parsers; it does not need Node, npm or
an internet connection to start (scans do use the network for OSV, EPSS and KEV unless
`--offline`). About 100 MB.

### Download and check

Linux and macOS:

```bash
V=1.0.0
curl -fsSLO "https://github.com/GRCSAC/nextfix/releases/download/v$V/nextfix-$V-linux-x64"
curl -fsSLO "https://github.com/GRCSAC/nextfix/releases/download/v$V/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS      # macOS: shasum -a 256 --check --ignore-missing SHA256SUMS
chmod +x "nextfix-$V-linux-x64"
sudo mv "nextfix-$V-linux-x64" /usr/local/bin/nextfix
nextfix --version
```

macOS keeps a downloaded program in quarantine until you allow it once: either right-click
the file in Finder and choose Open, or `xattr -d com.apple.quarantine nextfix`. The binary
carries an ad-hoc signature, not an Apple notarisation.

Windows (PowerShell):

```powershell
$V = "1.0.0"
Invoke-WebRequest "https://github.com/GRCSAC/nextfix/releases/download/v$V/nextfix-$V-win32-x64.exe" -OutFile nextfix.exe
Invoke-WebRequest "https://github.com/GRCSAC/nextfix/releases/download/v$V/SHA256SUMS" -OutFile SHA256SUMS
(Get-FileHash nextfix.exe -Algorithm SHA256).Hash.ToLower()   # compare with the win32-x64 line in SHA256SUMS
.\nextfix.exe --version
```

The bare `.exe` is unsigned; SmartScreen may ask once. The Windows installer (when it ships
with a release) carries a signed copy.

### Run

```bash
nextfix scan ./my-app                         # decisions on the terminal
nextfix scan ./my-app --json out.json --sarif out.sarif --fail-on Act     # CI gate (exit 3 on Act)
nextfix serve                                 # dashboards at http://127.0.0.1:8790, opens the browser
nextfix serve --host 0.0.0.0 --allow-host nextfix.internal --no-open      # for the team
```

`nextfix scan --help` and `nextfix serve --help` list every option. The first time the
dashboards open on the machine that runs them, they ask for the first administrator's name
and password; until that admin exists, other machines are refused.

State lives in one folder: `~/.nextfix` on Linux and macOS, `C:\Users\<you>\.nextfix` on
Windows. Set `NEXTFIX_HOME` to move it (or `--db <file>` for the history database alone).

| File | What |
|---|---|
| `nextfix.sqlite` (and `-wal`, `-shm` while running) | scan history, accounts, settings, exceptions, audit log |
| `cache.sqlite` | OSV, EPSS and KEV answers with their expiry; derived vulnerable symbols |

## Windows installer

Windows users can take `NextFix-Setup-<version>.exe` from the release instead of the bare
executable: a per-user install with no elevation, a Start Menu entry for the dashboards, the
install folder on the user PATH, and an Authenticode signature (publisher GRCSAC). It is also
on winget (`winget install GRCSAC.NextFix`) and Chocolatey (`choco install nextfix`) once each
release is approved there. How it is built and signed is in
[INSTALL-WINDOWS.md](INSTALL-WINDOWS.md).

## Docker

The image `ghcr.io/grcsac/nextfix:<version>` (also `:latest`) runs the server as the
unprivileged user `node`, keeps everything under `/data`, listens on 8790, and carries
[syft](https://github.com/anchore/syft) so `--image` scans work out of the box. Build it
yourself with `docker build -t nextfix -f packaging/Dockerfile .`.

Every published image is signed with cosign (keyless, through GitHub's OIDC identity):

```bash
cosign verify ghcr.io/grcsac/nextfix:1.0.0 \
  --certificate-identity-regexp '^https://github.com/GRCSAC/nextfix/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### Compose

```yaml
services:
  nextfix:
    image: ghcr.io/grcsac/nextfix:1.0.0
    container_name: nextfix
    restart: unless-stopped
    ports:
      - "8790:8790"                     # "127.0.0.1:8790:8790" to keep it local, behind a proxy
    volumes:
      - nextfix-data:/data              # database, caches, derived symbols
      - /var/run/docker.sock:/var/run/docker.sock   # only for --image scans of local images
      # - /srv/apps:/projects:ro        # projects to scan, read-only
    # The container's own defaults are --host 0.0.0.0 --port 8790 --no-open; add flags here.
    command: ["serve", "--allow-host", "nextfix.example.com", "--secure-cookies"]
    # group_add: ["<docker group id>"]  # Linux hosts: lets the node user use the socket (see below)
volumes:
  nextfix-data:
```

```bash
docker compose up -d
docker compose logs -f nextfix
```

### The first admin in Docker

Requests from your browser reach the container through Docker's bridge, not loopback, so
the "create the first admin on this machine" page is refused until an admin exists. Create
one from inside the container; it prompts for the password twice:

```bash
docker exec -it nextfix nextfix user add admin --role admin
```

Then open http://localhost:8790 and sign in. The same command recovers a locked-out
instance (`nextfix user password <name>`), and works while the server is running.

Two alternatives: `network_mode: host` on a Linux host makes the browser a loopback
client, so the first-run page works; and `--allow-open` (no accounts at all, everyone on
the machine is an admin) answers loopback only, which inside a container means only the
container itself, so it is of no use behind the bridge or a reverse proxy.

### Names, hosts and cookies

- The server answers to `localhost`, `127.0.0.1`, `[::1]` and every `--allow-host <name>`
  you give; any other name in the address bar gets 421 with the flag to add. There is no
  wildcard on purpose (it is the defence against DNS rebinding): list each name or address
  you use, for example `--allow-host nextfix.example.com --allow-host 10.0.0.12`.
- `--host 0.0.0.0` (the container's default) listens on every interface of the container;
  the `ports:` mapping decides who can reach it.
- `--secure-cookies` marks the session cookie `Secure`; use it as soon as TLS terminates in
  front of NextFix. Without TLS the flag locks you out, because the browser never sends the
  cookie back.
- `NEXTFIX_HOST` and `NEXTFIX_PORT` change the container's defaults when you would rather
  not repeat `command:`; the health check follows `NEXTFIX_PORT`.

### Image scans from the container

`nextfix scan /project --image myorg/app:1.2` runs the bundled syft. With the Docker
socket mounted it reads images from the host's daemon; without it, syft pulls from the
registry. On Linux the socket belongs to the `docker` group, so add that group to the
container (`group_add: ["$(getent group docker | cut -d: -f3)"]`); Docker Desktop on
Windows and macOS needs nothing extra. Mounting the socket hands the container control of
the Docker daemon: do it only on a host you would let NextFix's user administer anyway.

A one-off scan without the server:

```bash
docker run --rm -v "$PWD:/project:ro" -v nextfix-data:/data ghcr.io/grcsac/nextfix:1.0.0 \
  scan /project --json /data/report.json
```

## Upgrading

The database schema is versioned and migrates in place the first time a newer NextFix opens
it. Nothing undoes a migration, so the only way back to an older version is the backup. In
order:

1. Back up the database (next section).
2. Stop the server (`Ctrl-C`, or `docker compose down`).
3. Replace the executable, or change the image tag in the compose file.
4. Start it; the first line of output names the version, and `/api/health` reports it too.

Reports and VEX documents carry the version that produced them, so mixed histories stay
readable. The advisory cache needs no care: entries expire on their own.

## Backup and restore

What to keep is the state folder: `nextfix.sqlite` and, if you want to avoid re-fetching
advisories after a restore, `cache.sqlite`. The database runs in WAL mode, so copy it
either with the server stopped, or live through SQLite's own backup command, which produces a
consistent single file:

```bash
# stopped server, executable: the folder as it is
tar czf nextfix-backup-$(date +%F).tgz -C ~ .nextfix

# running server, with the sqlite3 tool installed
sqlite3 ~/.nextfix/nextfix.sqlite ".backup 'nextfix-backup-$(date +%F).sqlite'"

# Docker: the volume, with the container stopped
docker compose stop nextfix
docker run --rm -v nextfix-data:/data -v "$PWD:/backup" alpine \
  tar czf "/backup/nextfix-backup-$(date +%F).tgz" -C /data .
docker compose start nextfix
```

Restore is the reverse: stop the server, put `nextfix.sqlite` back (delete any stale
`nextfix.sqlite-wal` and `nextfix.sqlite-shm` beside it unless they came from the same
backup), start the server. A backup from an older version migrates forward on start, like
an upgrade. Passwords, sessions, API tokens and SSO settings are inside the database, so
a restored instance is complete; sessions that were open when the backup was taken are
simply signed out.

## Behind a reverse proxy with HTTPS

NextFix speaks plain HTTP; terminate TLS in a proxy on the same host or network and start
NextFix with the proxy's public name allowed and secure cookies on:

```bash
nextfix serve --host 127.0.0.1 --port 8790 --no-open --allow-host nextfix.example.com --secure-cookies
```

The proxy must pass the original `Host` header through (that is what `--allow-host`
checks) and set `X-Forwarded-Proto: https` (that is how NextFix knows cross-origin checks
should expect `https://`). It must not rewrite paths: the dashboard is served at `/` and
the API under `/api/`.

Caddy (automatic certificates):

```
nextfix.example.com {
    reverse_proxy 127.0.0.1:8790
}
```

nginx:

```nginx
server {
    listen 443 ssl http2;
    server_name nextfix.example.com;
    ssl_certificate     /etc/letsencrypt/live/nextfix.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/nextfix.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8790;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 1800s;      # a long scan streams progress; do not cut it short
    }
}
```

With Docker, point the proxy at the published port (`127.0.0.1:8790` on the host, or the
service name on a shared compose network) and keep `ports:` bound to `127.0.0.1` so the
only way in is through TLS.

Two things the proxy does not change:

- The first admin is still created from loopback as seen by NextFix: on the machine itself
  (`curl` or a browser on `http://127.0.0.1:8790`), or with `nextfix user add` (in Docker,
  through `docker exec`). NextFix does not trust `X-Forwarded-For` for that decision.
- The audit log records the address NextFix sees, which behind a proxy is the proxy's.
  Keep the proxy's access log if you need the client address.
