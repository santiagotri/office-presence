# Office Presence

Who is in the office right now, detected by device MAC addresses on the office LAN.
FastAPI + SQLite + one static page. Linux and macOS.

## How it works
Every `OP_SCAN_INTERVAL` seconds the service (optionally) ping-sweeps `OP_SUBNET` to populate the
ARP cache, then reads the neighbor table (`ip neigh` on Linux, `arp -an` on macOS). With
`OP_USE_SCAPY=1` + scapy installed + root, it also does an active ARP scan. Each MAC gets a `last_seen`.
A **profile** (person) owns one or more **devices** (MAC + label) and is *present* if any device was
seen within `OP_PRESENT_TIMEOUT` seconds.

## Install & run
```bash
git clone <repo> office-presence && cd office-presence
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
OP_SUBNET=192.168.1.0/24 .venv/bin/uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000
```
UI: `http://<machine>:8000/` · Swagger: `/docs` · OpenAPI JSON: `/openapi.json`.

Register people: create a profile, then open "Unknown devices" and assign the MACs you see, or type a MAC.

## Config (env vars)
| Var | Default | Meaning |
|---|---|---|
| `OP_DB_PATH` | `presence.db` | SQLite file |
| `OP_SCAN_INTERVAL` | `30` | seconds between scans |
| `OP_PRESENT_TIMEOUT` | `300` | seconds since last sighting to count as present |
| `OP_SUBNET` | *(empty)* | CIDR to sweep, e.g. `192.168.1.0/24` (max /22). Empty = only read ARP table |
| `OP_PING_SWEEP` | `1` | ping every host in `OP_SUBNET` before reading the table |
| `OP_USE_SCAPY` | `0` | active ARP scan (`pip install scapy`, needs root) |
| `OP_API_KEY` | *(empty)* | if set, all write endpoints require header `X-API-Key` |
| `OP_SCANNER` | `1` | set `0` to disable background scanning |

**If you expose the UI beyond the LAN, set `OP_API_KEY`** (and put it behind HTTPS). Reads stay public.

## API
- `GET /health`
- `GET /api/presence` → `{present: [...], absent: [...]}`
- `POST /api/scan` – scan now
- `GET|POST /api/profiles`, `GET|PUT|DELETE /api/profiles/{id}`
- `POST /api/profiles/{id}/devices` `{mac, label}`, `DELETE /api/profiles/{id}/devices/{mac}`
- `GET /api/devices/unknown?since=<seconds>` – seen MACs not assigned to anyone

MACs are accepted in any common format and stored as `aa:bb:cc:dd:ee:ff`.

## ⚠️ Private / random MAC addresses
iOS (≥14), Android (≥10), Windows and macOS Sequoia use a **per-network private MAC** by default,
and some rotate it periodically. Each person should either:
- turn it off for the office Wi-Fi (iOS: Settings → Wi-Fi → (i) → Private Wi-Fi Address → Off / Fixed;
  Android: Wi-Fi → network → Privacy → Use device MAC), **or**
- register the MAC shown for *that* network (it's stable per network when set to "Fixed").
"Rotating" mode will break detection. Also note phones sleep Wi-Fi aggressively; a ping sweep
(`OP_SUBNET`) plus a 5 min timeout handles most of that. Wired/Wi-Fi client isolation on the AP
hides devices entirely.

## Run as a service
### Linux (systemd) – `/etc/systemd/system/office-presence.service`
```ini
[Unit]
Description=Office Presence
After=network-online.target
Wants=network-online.target

[Service]
User=presence
WorkingDirectory=/opt/office-presence
Environment=OP_SUBNET=192.168.1.0/24
Environment=OP_DB_PATH=/opt/office-presence/presence.db
Environment=OP_API_KEY=change-me
ExecStart=/opt/office-presence/.venv/bin/uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
`sudo systemctl daemon-reload && sudo systemctl enable --now office-presence`.
For scapy mode run as root or grant `CAP_NET_RAW` (`AmbientCapabilities=CAP_NET_RAW`).

### macOS (launchd)
Create `~/Library/LaunchAgents/com.office.presence.plist` with `ProgramArguments` =
`/path/.venv/bin/uvicorn app.main:create_app --factory --host 0.0.0.0 --port 8000`,
`WorkingDirectory` = repo path, `EnvironmentVariables` for the `OP_*` vars, `RunAtLoad` and `KeepAlive` true,
then `launchctl load ~/Library/LaunchAgents/com.office.presence.plist`. macOS will ask to allow
incoming connections for Python the first time.

### Docker (Linux only)
Needs host networking to see the LAN ARP table:
```bash
docker build -t office-presence .
docker run -d --net=host -e OP_SUBNET=192.168.1.0/24 -v $PWD/data:/data office-presence
```
Docker Desktop on macOS can't see the host LAN this way; run natively there.

## Tests
```bash
.venv/bin/pip install -r requirements-dev.txt && .venv/bin/python -m pytest -q
```
The scanner is mocked; parsers are tested against sample `ip neigh` / `arp -an` output.
