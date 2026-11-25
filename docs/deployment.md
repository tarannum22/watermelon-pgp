# Deploying watermelon-pgp

`watermelon serve` is the whole application: the web UI and the job engine in one process.
It needs three things:

- a **data directory** for the SQLite database (`WATERMELON_DATA_DIR`),
- the **master key**, which encrypts every secret key in the database, and
- read/write access to the **job folders** (the folders your SFTP server reads and writes).

Every command-line flag has a `WATERMELON_*` environment variable; `watermelon serve --help`
lists them.

## The master key

`watermelon init` creates the master key next to the database unless you say otherwise. In
production, keep it **outside** the data directory, so a backup or a stolen copy of one never
contains the other:

- a file: `WATERMELON_MASTER_KEY_FILE=/etc/watermelon/key/master.key`. It must be readable only
  by its owner (`0600` or `0400`); watermelon refuses a key file other users can read.
- or the key itself, hex-encoded, in `WATERMELON_MASTER_KEY` (for secret stores that inject
  environment variables).

Back the master key up once, somewhere safe and separate from the database backups. Without it
the secret keys in the database cannot be recovered.

## systemd

[`contrib/systemd/watermelon.service`](../contrib/systemd/watermelon.service) runs watermelon as
an unprivileged user with a tight sandbox: it can write only to its state directory and the
job folders you allow.

```sh
sudo useradd --system --home-dir /var/lib/watermelon --shell /usr/sbin/nologin watermelon
sudo install -m 0755 watermelon /usr/local/bin/watermelon
sudo install -d -o watermelon -g watermelon -m 0700 /var/lib/watermelon /etc/watermelon/key
sudo install -m 0640 contrib/systemd/watermelon.env /etc/watermelon/

# Database, master key and admin password
sudo -u watermelon env WATERMELON_DATA_DIR=/var/lib/watermelon \
    WATERMELON_MASTER_KEY_FILE=/etc/watermelon/key/master.key watermelon init

sudo install -m 0644 contrib/systemd/watermelon.service /etc/systemd/system/
sudo systemctl edit watermelon       # allow the job folders, see below
sudo systemctl enable --now watermelon
journalctl -u watermelon -f
```

The sandbox makes the whole file system read-only for the service, so list the job folders:

```ini
# systemctl edit watermelon
[Service]
ReadWritePaths=/srv/sftp
```

Folder permissions: the `watermelon` user needs read/write access to every job's input, output,
`processed/` and `failed/` folders. A common setup is a shared group: add `watermelon` and the
SFTP users to it and make the folders group-writable with the setgid bit
(`chmod 2770`). The unit's `UMask=0027` makes output files group-readable.

Settings live in [`/etc/watermelon/watermelon.env`](../contrib/systemd/watermelon.env).
`systemctl reload watermelon` reloads the TLS certificate; other changes need a restart.
On stop, running jobs finish their current file first.

## Docker

The image runs as uid/gid `10001`, keeps its data in `/data`, listens on port 8080 and logs JSON.

```sh
docker build -t watermelon-pgp .          # or use ghcr.io/tarannum22/watermelon-pgp

# Once: database, master key and admin password
docker run --rm -it -v watermelon-data:/data \
    -v /srv/watermelon-key:/key -e WATERMELON_MASTER_KEY_FILE=/key/master.key \
    watermelon-pgp init

docker run -d --name watermelon --restart unless-stopped \
    -p 127.0.0.1:8080:8080 \
    -v watermelon-data:/data \
    -v /srv/watermelon-key:/key:ro -e WATERMELON_MASTER_KEY_FILE=/key/master.key \
    -v /srv/sftp:/srv/sftp \
    watermelon-pgp
```

- Mount job folders at the **same path** inside the container, so the paths you enter in the UI
  are the real ones, and make them writable for uid `10001` (e.g. a shared group, as above, with
  `--group-add <gid>`).
- `/srv/watermelon-key` must be owned by uid `10001` and not readable by others. Docker/Compose
  secrets are usually mounted world-readable and are refused; pass the key through
  `WATERMELON_MASTER_KEY` instead if that's what your platform offers.
- Publish the port on `127.0.0.1` unless TLS is set up (next section).
- `docker stop` lets running jobs finish their current file; give it time with `--stop-timeout`
  if you process very large files.

## HTTPS

The UI must be reached over HTTPS once it leaves the machine: it handles the admin password and
secret-key exports. Two ways:

**Built in.** Give watermelon a certificate and key (PEM):

```sh
WATERMELON_BIND=0.0.0.0:8443
WATERMELON_TLS_CERT=/etc/watermelon/tls/fullchain.pem
WATERMELON_TLS_KEY=/etc/watermelon/tls/privkey.pem
```

Session cookies are then marked `Secure` and HSTS is sent. After renewing the certificate, send
`SIGHUP` (`systemctl reload watermelon`, `docker kill -s HUP watermelon`): new connections use
the new certificate, no restart needed.

**Behind a reverse proxy.** Keep watermelon on `127.0.0.1:8080`, terminate TLS in the proxy,
and set `WATERMELON_SECURE_COOKIES=true`. The proxy must pass the `Host` header through
unchanged (form submissions are checked against it). Caddy:

```
pgp.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
}
```

Behind a proxy every request appears to come from the proxy's address, so the login rate limit
applies to all clients together. With a single admin account that is acceptable.

## Logs and monitoring

- `WATERMELON_LOG_FORMAT=json` writes one JSON object per line to stderr; `text` is the default.
- `WATERMELON_LOG=debug` (or `warn`, `error`) changes the level; the default is `info`.
- `GET /healthz` returns `200 {"status":"ok"}` when the database is reachable, `503` otherwise.
  It needs no login.
- Logged: every page request (method, path, status, duration, client), job passes that
  processed or failed files, paused jobs, and errors. The full record of who did what is the
  audit log, in the UI or with `watermelon audit`.

## Backups and restore

```sh
watermelon backup /backups/watermelon-$(date +%F).db
```

writes a consistent snapshot of the database while the service is running. It does **not**
include the master key, by design.

To restore: stop the service, delete `watermelon.db-wal` and `watermelon.db-shm` from the data
directory if present (they belong to the old database and would corrupt the restored one),
copy the snapshot to `<data dir>/watermelon.db` (owned by the service user, mode `0600`), and
start the service with the **same master key**. watermelon checks at startup that the key
matches the database and refuses to start otherwise.

## Upgrading

Stop the service, replace the binary (or pull the new image), start it again. Database schema
migrations run automatically at startup.

Before migrating, watermelon copies the database as it was to
`<data dir>/watermelon.db.schema-v<N>.bak`, where N is the old schema version. Older releases
can't open a migrated database, so to go back: stop the service, put the old binary back, and
restore that copy as described above. Delete the copy once you're happy with the new version;
like the database, it contains your keys (sealed under the master key).

`watermelon backup` run with the *new* binary migrates the database before it copies it, so
for a backup the old release can read, run it with the old binary, before replacing it.
