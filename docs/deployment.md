# Deploying watermelon-pgp

`watermelon serve` is the whole application: the web UI and the job engine in one process.
It needs three things:

- a **data directory** for the SQLite database (`WATERMELON_DATA_DIR`),
- the **master key**, which encrypts every secret key in the database, and
- read/write access to the **job folders** (the folders your SFTP server reads and writes).

Every command-line flag has a `WATERMELON_*` environment variable; `watermelon serve --help`
lists them.

On Linux, run it with [systemd](#systemd) or [Docker](#docker); on Windows, as a
[Windows service](#windows-server).

## The master key

`watermelon init` creates the master key next to the database unless you say otherwise. In
production, keep it **outside** the data directory, so a backup or a stolen copy of one never
contains the other:

- a file: `WATERMELON_MASTER_KEY_FILE=/etc/watermelon/key/master.key`. It must be readable only
  by its owner (`0600` or `0400`); watermelon refuses a key file other users can read. On
  Windows the same goes for its access list; see
  [the data directory and the master key](#the-data-directory-and-the-master-key).
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
the new certificate, no restart needed. On Windows, see [HTTPS on Windows](#https-on-windows).

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
- `WATERMELON_LOG_FILE` (`--log-file`) appends the log to a file instead of stderr. The Windows
  service always logs to a file ([below](#the-windows-service)).
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

## Windows Server

watermelon runs natively on Windows Server (x86_64) as a Windows service; WSL2 is not needed.
CI tests it on Windows Server 2025. The commands below are for an **elevated** PowerShell ("Run
as administrator"). The layout used here:

| What | Where |
|---|---|
| Program | `C:\Program Files\WatermelonPGP\watermelon.exe` |
| Data directory | `C:\ProgramData\WatermelonPGP\data` |
| Master key | `C:\ProgramData\WatermelonPGP\key\master.key` |
| Service | `watermelon`, running as `NT SERVICE\watermelon` |

Any other folders or drives work the same way (e.g. `D:\WatermelonPGP\data`); use them in every
command below.

### Install

Download `watermelon-pgp-vX.Y.Z-x86_64-pc-windows-msvc.zip` and `SHA256SUMS` from the
[GitHub releases](https://github.com/tarannum22/watermelon-pgp/releases) (the first release after
0.2.0 has it), check the zip against `SHA256SUMS`, and unpack it:

```powershell
$zip = "watermelon-pgp-vX.Y.Z-x86_64-pc-windows-msvc.zip"
$expected = ((Get-Content SHA256SUMS) -match [regex]::Escape($zip)) -split '\s+' | Select-Object -First 1
if ((Get-FileHash $zip -Algorithm SHA256).Hash -ne $expected) { throw "$zip does not match SHA256SUMS" }

Expand-Archive $zip -DestinationPath $env:TEMP\watermelon-pgp
New-Item -ItemType Directory "C:\Program Files\WatermelonPGP" -Force
Copy-Item "$env:TEMP\watermelon-pgp\*\*" "C:\Program Files\WatermelonPGP" -Recurse
$env:Path += ";C:\Program Files\WatermelonPGP"    # this shell; add it to the system Path to keep it
watermelon --version
```

The zip holds `watermelon.exe` with the C runtime linked in (no Visual C++ redistributable
needed), plus this documentation. `watermelon.exe` isn't code-signed yet, so SmartScreen may warn
about it.

### The data directory and the master key

Every command works on a data directory: `.\data` relative to the current folder unless you
choose another with `--data-dir` or `WATERMELON_DATA_DIR`. For a server, choose it explicitly,
along with a master key outside it (see [The master key](#the-master-key)):

```powershell
$env:WATERMELON_DATA_DIR = "C:\ProgramData\WatermelonPGP\data"
$env:WATERMELON_MASTER_KEY_FILE = "C:\ProgramData\WatermelonPGP\key\master.key"
watermelon init      # prompts for the admin password of the web UI
```

`init` creates the folders it needs, the database and the master key so that **only the account
that ran it** can access them (their access lists don't inherit from `C:\ProgramData`, which every
local user can read). If the data directory already exists and others can access it, `init`
restricts it too. `service install` then hands both over to the service account (next section).

The master key file is refused, the way Unix refuses one that isn't `0600`, if its access list
lets in anyone other than the account running watermelon, LocalSystem, Administrators and the
file's owner, or if the owner is anyone other than those or a service account
(`NT SERVICE\…`): an owner can always change the access list. The error says which `icacls`
commands fix it. `init` likewise refuses a data directory owned by another account. Because
Administrators and service-account owners count, an administrator can still run commands such
as `backup` and `audit` against the service's data from an elevated prompt.

### The Windows service

After `init`, in the same elevated PowerShell (so the `WATERMELON_*` variables above still
apply), install the service with the installed `watermelon.exe`. It runs `serve`, so it takes
the same options ([docs/cli.md](cli.md#serve)); add `--tls-cert`/`--tls-key` here for HTTPS
([below](#https-on-windows)):

```powershell
watermelon service install --bind 127.0.0.1:8080
icacls D:\sftp /grant "NT SERVICE\watermelon:(OI)(CI)M"    # the job folders, see below
Start-Service watermelon
(Invoke-WebRequest http://127.0.0.1:8080/healthz).Content   # {"status":"ok"}
```

What `service install` does:

- Creates the service `watermelon` (display name "WatermelonPGP"; another name with `--name`),
  started automatically with Windows. It runs the `watermelon.exe` you ran `install` with, so
  put it where it stays first.
- Writes the data directory, master key file, log file, `--log-format` and the `serve` options
  into the service's command line, with absolute paths. Nothing secret goes there: the master
  key must be a file, and `install` refuses `WATERMELON_MASTER_KEY`. It refuses to install
  before `init`.
- Runs it as the virtual account **`NT SERVICE\watermelon`**: no password to manage, and no
  rights beyond what you grant it.
- Makes that account the **owner** of the data directory, everything in it and the master key
  file, and lets only it, LocalSystem and Administrators access them; files created in the data
  directory later get the same. The folder that holds the key keeps its access list; the
  service opens the key by its full path.
- Lets the account read the `--tls-cert` and `--tls-key` files, and write a `--log-file` outside
  the data directory, by adding an entry and keeping the others. It prints what it changed.
  Job folders are up to you.
- Restarts the service if it fails: after 5 seconds, again after 5 seconds, then every minute
  (the count resets after a day).

If any step fails, the service is removed again. To change a setting later, uninstall and
install again; the data stays.

**Stopping.** `Stop-Service watermelon` (and `Restart-Service`) stop the web server first, then
let running jobs finish their current file, as SIGTERM does on Linux. While a job makes
progress the service keeps reporting that it's stopping, so a multi-GB file gets the time it
needs; after 90 seconds without progress it stops reporting, and Windows may consider it hung.
At Windows shutdown it gets up to 5 minutes; a file still unfinished then is processed again
from the start after the next boot.

**Uninstalling.** `watermelon service uninstall` stops the service if it's running (waiting
while jobs finish their current file, but giving up when it makes no more progress, or after
30 minutes) and removes it. The data directory and master key stay, still owned by the service
account; Administrators keep access.

**Logs.** The service has no console; it appends its log to `<data dir>\watermelon.log`, or the
file given with `--log-file` at install. If it can't open that file, it writes why to
`<data dir>\watermelon.log` and doesn't start. Follow it from an elevated prompt:

```powershell
Get-Content C:\ProgramData\WatermelonPGP\data\watermelon.log -Tail 50 -Wait
```

The file isn't rotated: watch its size, and to start a new one stop the service, rename the
file and start it again. `--log-format json` at install writes one JSON object per line. To
change the level, set `WATERMELON_LOG` in the service's environment and restart:

```powershell
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\watermelon -Name Environment `
    -Type MultiString -Value "WATERMELON_LOG=debug"
Restart-Service watermelon
```

Don't put `WATERMELON_MASTER_KEY` there: it would override the key file. `GET /healthz` works
as on Linux (see [Logs and monitoring](#logs-and-monitoring)).

### Job folders

The service account needs to read, write and delete in every job's input, output, `processed\`
and `failed\` folders (`processed\` and `failed\` are created if missing). Grant it on the folder
your SFTP server writes into; `(OI)(CI)` passes it on to files and subfolders:

```powershell
icacls D:\sftp /grant "NT SERVICE\watermelon:(OI)(CI)M"
```

Folders are entered as drive paths (`D:\sftp\acme\in`) or UNC paths
(`\\fileserver\sftp\acme\in`), on the job form or with `watermelon job add`.

- **Network shares:** a virtual account such as `NT SERVICE\watermelon` reaches other machines as
  the server's **computer account**, `DOMAIN\HOST$`. Grant that account change access on the
  share and modify access on its folders. On a server that isn't in a domain, the computer
  account has no identity on the network, so shares that need a login don't work. `service install`
  can't run the service as a domain account or gMSA yet (see [Known limits](#known-limits)).
- **Mapped drive letters** (`Z:\`) belong to a user's logon session; the service doesn't see
  them. Use the UNC path.
- **Uploads in progress:** besides waiting until a file's size and modification time stop
  changing, a job leaves a file alone while another program (the SFTP server) still has it open
  for writing, without logging it as failed, and picks it up once it's closed. While a file is
  being processed, others can read it but not change or delete it.
- **Hidden files:** files with the *hidden* or *system* attribute (`Thumbs.db`, `desktop.ini`)
  are ignored, like names starting with a dot and the usual temporary upload names (`*.part`,
  `*.filepart`, `*.tmp`, `*.crdownload`, `*.partial`).
- **Output being written** goes to a temporary file in the output folder,
  `.<name>.<pid>-<n>.watermelon-tmp`, which is renamed to its final name once complete. On Windows
  it isn't marked hidden, so a process that collects files from the output folder should ignore
  names ending in `.watermelon-tmp` (or starting with a dot). Temporary files left by a crash are
  removed after 15 minutes.

### HTTPS on Windows

Give the service a PEM certificate chain and key with `--tls-cert` and `--tls-key` when you
install it (see [HTTPS](#https) for what changes). `service install` lets the service account
read those two files. If renewal replaces them with new files rather than rewriting them, the
new ones get the folder's access list instead, so grant read access on the folder too:

```powershell
icacls C:\ProgramData\WatermelonPGP\tls /grant "NT SERVICE\watermelon:(OI)(CI)R"
```

After renewing the certificate, reload it without a restart:

```powershell
sc.exe control watermelon paramchange
```

With [win-acme](https://www.win-acme.com/), store the certificate as PEM files in that folder
and run that command as the installation step after each renewal.

To bind beyond loopback (e.g. `--bind 0.0.0.0:8443`), allow the port in Windows Firewall:

```powershell
New-NetFirewallRule -DisplayName "WatermelonPGP" -Direction Inbound -Protocol TCP -LocalPort 8443 -Action Allow
```

### Backups and upgrades

From an elevated prompt, an administrator can back up the database while the service runs:

```powershell
watermelon --data-dir C:\ProgramData\WatermelonPGP\data `
    --master-key C:\ProgramData\WatermelonPGP\key\master.key `
    backup "D:\backups\watermelon-$(Get-Date -Format yyyy-MM-dd).db"
```

The copy is readable only by you. As on Linux, it doesn't include the master key: copy
`master.key` once, somewhere safe and separate.

To restore: `Stop-Service watermelon`, delete `watermelon.db-wal` and `watermelon.db-shm` from
the data directory if present, **copy** the snapshot to `<data dir>\watermelon.db` with
`Copy-Item` (a copy takes the data directory's access list, so the service can open it; a moved
file keeps the access list it had), and `Start-Service watermelon` with the same master key.

To upgrade: `Stop-Service watermelon`, replace `C:\Program Files\WatermelonPGP\watermelon.exe`
with the new one, `Start-Service watermelon`. As described in [Upgrading](#upgrading), a database
upgrade first keeps a copy of the old database in the data directory
(`watermelon.db.schema-v<N>.bak`); for a backup the old release can read, run `backup` with the
old `watermelon.exe` before replacing it.

### Known limits

- The service runs as its virtual account (`NT SERVICE\<name>`) only; a custom, domain or
  group-managed service account isn't supported yet, so network shares must allow the computer
  account.
- To change a setting of an installed service, uninstall and install it again.
- No jobs-only service (`run`): the service always serves the web UI too.
- The log is a plain file without rotation; nothing goes to the Event Log.
- An OS shutdown can stop the service before a large file is finished; the file is processed
  again from the start on the next start.
- The TLS certificate comes from PEM files, not the Windows certificate store.
- Temporary output files aren't hidden (see [Job folders](#job-folders)).
- `watermelon.exe` isn't code-signed, and there's no installer, winget or Scoop package yet.
- x86_64 only. CI tests Windows Server 2025; Server 2022 isn't tested.
