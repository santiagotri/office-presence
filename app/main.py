import asyncio
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

from . import scanner
from .config import Settings
from .db import DB
from .notify import DEFAULT_URL, Notifier

log = logging.getLogger("office-presence")
STATIC = Path(__file__).parent / "static"


class DeviceIn(BaseModel):
    mac: str = Field(examples=["aa:bb:cc:dd:ee:ff"])
    label: str = ""

    @field_validator("mac")
    @classmethod
    def _norm(cls, v):
        return scanner.normalize_mac(v)


class ProfileIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    devices: list[DeviceIn] = []


class ProfileUpdate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class NameIn(BaseModel):
    name: str = Field("", max_length=100, description="Empty clears the name")


class OpenClawIn(BaseModel):
    enabled: bool = False
    url: str = Field(DEFAULT_URL, max_length=500)
    token: Optional[str] = Field(None, description="None/omitted keeps the stored token, '' clears it")
    agent_id: str = Field("", max_length=100, description="OpenClaw agentId, empty = gateway default")
    channel: str = Field("", max_length=100, description="Direct delivery channel (needs `to` too)")
    to: str = Field("", max_length=200)


class RuleIn(BaseModel):
    profile_id: Optional[int] = Field(None, description="None = every profile")
    trigger: str = Field("both", pattern="^(arrive|leave|both)$")
    enabled: bool = True


class DiscoverIn(BaseModel):
    subnet: str = Field("", examples=["192.168.1.0/24"], description="Empty = OP_SUBNET or auto-detect")


def create_app(settings: Optional[Settings] = None, scan_fn=None, discover_fn=None, notifier=None) -> FastAPI:
    settings = settings or Settings()
    scan_fn = scan_fn or scanner.scan
    discover_fn = discover_fn or scanner.discover
    db = DB(settings.db_path)
    notifier = notifier or Notifier(db)
    state = {"last_scan": None, "last_error": None}

    def record(found):
        db.record(found, timeout=settings.present_timeout)
        for ev in db.profile_transitions():
            notifier.submit(ev)  # queued; delivered on the notifier thread

    def do_scan():
        try:
            record(scan_fn(settings))
            state["last_scan"], state["last_error"] = time.time(), None
        except Exception as e:  # noqa: BLE001
            state["last_error"] = str(e)
            log.exception("scan failed")

    async def loop():
        while True:
            await asyncio.to_thread(do_scan)
            await asyncio.sleep(settings.scan_interval)

    @asynccontextmanager
    async def lifespan(app):
        task = asyncio.create_task(loop()) if settings.scanner_enabled else None
        yield
        if task:
            task.cancel()

    app = FastAPI(title="Office Presence", version="1.0.0", lifespan=lifespan,
                  description="Who is in the office, detected by device MAC on the LAN.")
    app.state.db, app.state.settings, app.state.do_scan, app.state.notifier = db, settings, do_scan, notifier

    def require_key(x_api_key: Optional[str] = Header(None)):
        if settings.api_key and x_api_key != settings.api_key:
            raise HTTPException(401, "invalid or missing X-API-Key")

    def alias(mac):
        r = db.q("SELECT name FROM aliases WHERE mac=?", (mac,)).fetchone()
        return r["name"] if r else ""

    def device_info(mac, now, limit=0):
        s, events = db.history(mac, limit) if limit else (
            db.q("SELECT * FROM sightings WHERE mac=?", (mac,)).fetchone(), [])
        last = s["last_seen"] if s else None
        present = bool(last and now - last <= settings.present_timeout)
        out = {"name": alias(mac), "ip": s["ip"] if s else None, "first_seen": s["first_seen"] if s else None,
               "last_seen": last, "present": present,
               "arrived_at": s["arrived_at"] if s and present else None}
        if limit:
            out["events"] = events
        return out

    def profile_out(p):
        now = time.time()
        devs = []
        for d in db.q("SELECT mac, label FROM devices WHERE profile_id=? ORDER BY mac", (p["id"],)):
            devs.append({"mac": d["mac"], "label": d["label"], **device_info(d["mac"], now, 10)})
        lasts = [d["last_seen"] for d in devs if d["last_seen"]]
        return {"id": p["id"], "name": p["name"], "present": any(d["present"] for d in devs),
                "last_seen": max(lasts) if lasts else None, "devices": devs}

    def get_profile(pid):
        p = db.q("SELECT * FROM profiles WHERE id=?", (pid,)).fetchone()
        if not p:
            raise HTTPException(404, "profile not found")
        return p

    def add_device(pid, d: DeviceIn):
        owner = db.q("SELECT profile_id FROM devices WHERE mac=?", (d.mac,)).fetchone()
        if owner and owner["profile_id"] != pid:
            raise HTTPException(409, f"MAC {d.mac} already belongs to profile {owner['profile_id']}")
        db.q("INSERT OR REPLACE INTO devices(mac, profile_id, label) VALUES(?,?,?)",
             (d.mac, pid, d.label or alias(d.mac)))

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/health", tags=["meta"])
    def health():
        return {"status": "ok", "last_scan": state["last_scan"], "last_error": state["last_error"],
                "scan_interval": settings.scan_interval, "present_timeout": settings.present_timeout,
                "auth_required": bool(settings.api_key)}

    @app.get("/api/presence", tags=["presence"])
    def presence():
        profiles = [profile_out(p) for p in db.q("SELECT * FROM profiles ORDER BY name COLLATE NOCASE")]
        return {"timestamp": time.time(), "present": [p for p in profiles if p["present"]],
                "absent": [p for p in profiles if not p["present"]]}

    @app.post("/api/scan", tags=["presence"], dependencies=[Depends(require_key)])
    async def scan_now():
        await asyncio.to_thread(do_scan)
        return {"last_scan": state["last_scan"], "last_error": state["last_error"]}

    @app.post("/api/discover", tags=["devices"], dependencies=[Depends(require_key)])
    async def discover(body: Optional[DiscoverIn] = None):
        """Actively scan the LAN now and list every visible device, with its current owner if any."""
        try:
            res = await asyncio.to_thread(discover_fn, settings, body.subnet if body else "")
        except ValueError as e:
            raise HTTPException(422, str(e))
        except Exception as e:  # noqa: BLE001
            raise HTTPException(500, f"scan failed: {e}")
        skip = db.ignored_macs()
        res["devices"] = [d for d in res["devices"] if d["mac"] not in skip]
        record({d["mac"]: d["ip"] for d in res["devices"]})
        owners = {r["mac"]: (r["profile_id"], r["name"], r["label"]) for r in db.q(
            "SELECT d.mac, d.profile_id, d.label, p.name FROM devices d JOIN profiles p ON p.id=d.profile_id")}
        for d in res["devices"]:
            o = owners.get(d["mac"])
            d["profile_id"], d["profile_name"], d["label"] = o if o else (None, None, "")
            d["name"] = alias(d["mac"])
            d["first_seen"] = db.q("SELECT first_seen FROM sightings WHERE mac=?", (d["mac"],)).fetchone()[0]
        return {"timestamp": time.time(), **res}

    @app.put("/api/devices/{mac}/name", tags=["devices"], dependencies=[Depends(require_key)])
    def set_name(mac: str, body: NameIn):
        """Name any MAC, assigned to a profile or not. An empty name clears it."""
        try:
            mac = scanner.normalize_mac(mac)
        except ValueError as e:
            raise HTTPException(422, str(e))
        name = body.name.strip()
        if name:
            db.q("INSERT INTO aliases(mac, name) VALUES(?,?) ON CONFLICT(mac) DO UPDATE SET name=excluded.name",
                 (mac, name))
        else:
            db.q("DELETE FROM aliases WHERE mac=?", (mac,))
        return {"mac": mac, "name": name}

    def mac_or_422(mac):
        try:
            return scanner.normalize_mac(mac)
        except ValueError as e:
            raise HTTPException(422, str(e))

    @app.delete("/api/devices/{mac}", tags=["devices"], status_code=204, dependencies=[Depends(require_key)])
    def forget_device(mac: str, ignore: bool = False):
        """Delete an unassigned device: its sightings, events and name. It reappears fresh if seen
        again, unless `ignore=true`, which also hides it from scans until un-ignored."""
        mac = mac_or_422(mac)
        owner = db.q("SELECT profile_id FROM devices WHERE mac=?", (mac,)).fetchone()
        if owner:
            raise HTTPException(409, f"MAC {mac} belongs to profile {owner['profile_id']}; remove it there first")
        name = alias(mac)
        if not db.forget(mac) and not ignore:
            raise HTTPException(404, "device not found")
        if ignore:
            db.q("INSERT OR REPLACE INTO ignored(mac, name, ignored_at) VALUES(?,?,?)", (mac, name, time.time()))

    @app.get("/api/devices/ignored", tags=["devices"])
    def ignored_devices():
        """MACs hidden permanently; skipped by scans, discover and the unknown list."""
        return [dict(r) for r in db.q("SELECT mac, name, ignored_at FROM ignored ORDER BY ignored_at DESC")]

    @app.delete("/api/devices/ignored/{mac}", tags=["devices"], status_code=204, dependencies=[Depends(require_key)])
    def unignore_device(mac: str):
        mac = mac_or_422(mac)
        if db.q("DELETE FROM ignored WHERE mac=?", (mac,)).rowcount == 0:
            raise HTTPException(404, "MAC not ignored")

    @app.get("/api/devices/{mac}/history", tags=["devices"])
    def device_history(mac: str, limit: int = 50):
        """first_seen / last_seen / arrived_at plus the arrival & departure event log (newest first)."""
        try:
            mac = scanner.normalize_mac(mac)
        except ValueError as e:
            raise HTTPException(422, str(e))
        if not db.q("SELECT 1 FROM sightings WHERE mac=?", (mac,)).fetchone():
            raise HTTPException(404, "device never seen")
        return {"mac": mac, **device_info(mac, time.time(), max(1, min(limit, 500)))}

    @app.get("/api/profiles", tags=["profiles"])
    def list_profiles():
        return [profile_out(p) for p in db.q("SELECT * FROM profiles ORDER BY name COLLATE NOCASE")]

    @app.post("/api/profiles", tags=["profiles"], status_code=201, dependencies=[Depends(require_key)])
    def create_profile(body: ProfileIn):
        if db.q("SELECT 1 FROM profiles WHERE name=?", (body.name,)).fetchone():
            raise HTTPException(409, "profile name already exists")
        pid = db.q("INSERT INTO profiles(name) VALUES(?)", (body.name,)).lastrowid
        try:
            for d in body.devices:
                add_device(pid, d)
        except HTTPException:
            db.q("DELETE FROM profiles WHERE id=?", (pid,))
            raise
        return profile_out(get_profile(pid))

    @app.get("/api/profiles/{pid}", tags=["profiles"])
    def read_profile(pid: int):
        return profile_out(get_profile(pid))

    @app.put("/api/profiles/{pid}", tags=["profiles"], dependencies=[Depends(require_key)])
    def update_profile(pid: int, body: ProfileUpdate):
        get_profile(pid)
        clash = db.q("SELECT id FROM profiles WHERE name=? AND id!=?", (body.name, pid)).fetchone()
        if clash:
            raise HTTPException(409, "profile name already exists")
        db.q("UPDATE profiles SET name=? WHERE id=?", (body.name, pid))
        return profile_out(get_profile(pid))

    @app.delete("/api/profiles/{pid}", tags=["profiles"], status_code=204, dependencies=[Depends(require_key)])
    def delete_profile(pid: int):
        get_profile(pid)
        db.q("DELETE FROM profiles WHERE id=?", (pid,))

    @app.post("/api/profiles/{pid}/devices", tags=["devices"], status_code=201, dependencies=[Depends(require_key)])
    def post_device(pid: int, body: DeviceIn):
        get_profile(pid)
        add_device(pid, body)
        return profile_out(get_profile(pid))

    @app.delete("/api/profiles/{pid}/devices/{mac}", tags=["devices"], status_code=204, dependencies=[Depends(require_key)])
    def delete_device(pid: int, mac: str):
        try:
            mac = scanner.normalize_mac(mac)
        except ValueError as e:
            raise HTTPException(422, str(e))
        if db.q("DELETE FROM devices WHERE mac=? AND profile_id=?", (mac, pid)).rowcount == 0:
            raise HTTPException(404, "device not found on this profile")

    @app.get("/api/devices/unknown", tags=["devices"])
    def unknown_devices(since: Optional[int] = None):
        """MACs seen on the network not assigned to any profile. `since` = seconds back (default: present timeout x 12)."""
        cutoff = time.time() - (since or settings.present_timeout * 12)
        rows = db.q("""SELECT s.mac, COALESCE(a.name, '') AS name, s.ip, s.first_seen, s.last_seen
                       FROM sightings s LEFT JOIN devices d ON d.mac=s.mac LEFT JOIN aliases a ON a.mac=s.mac
                       WHERE d.mac IS NULL AND s.mac NOT IN (SELECT mac FROM ignored) AND s.last_seen>=?
                       ORDER BY s.last_seen DESC""", (cutoff,))
        return [dict(r) for r in rows]

    def oc_out():
        c = notifier.config()
        tok = c.pop("token", "") or ""
        c["token_set"] = bool(tok)
        c["token_masked"] = (tok[:3] + "…" + tok[-3:]) if len(tok) > 8 else ("•••" if tok else "")
        c.setdefault("enabled", False)
        for k in ("agent_id", "channel", "to"):
            c.setdefault(k, "")
        return c

    @app.get("/api/integrations/openclaw", tags=["events"])
    def get_openclaw():
        """Webhook config. The token is never returned, only masked. OP_OPENCLAW_TOKEN overrides it."""
        return oc_out()

    @app.put("/api/integrations/openclaw", tags=["events"], dependencies=[Depends(require_key)])
    def put_openclaw(body: OpenClawIn):
        cur = db.integration("openclaw")
        new = body.model_dump(exclude={"token"})
        new["token"] = cur.get("token", "") if body.token is None else body.token.strip()
        if bool(new["channel"]) != bool(new["to"]):
            raise HTTPException(422, "channel and to must be set together (or both empty)")
        db.set_integration("openclaw", new)
        return oc_out()

    @app.post("/api/integrations/openclaw/test", tags=["events"], dependencies=[Depends(require_key)])
    async def test_openclaw():
        """Send a test event synchronously and return the delivery result."""
        cfg = notifier.config()
        if not cfg.get("url"):
            raise HTTPException(422, "no webhook URL configured")
        ev = {"event": "test", "profile": "Prueba", "profile_id": None, "ts": time.time(), "devices": []}
        ok = await asyncio.to_thread(notifier.deliver, cfg, ev)
        last = db.q("SELECT * FROM deliveries ORDER BY id DESC LIMIT 1").fetchone()
        return {"ok": ok, "delivery": dict(last)}

    @app.get("/api/integrations/openclaw/deliveries", tags=["events"])
    def deliveries(limit: int = 30):
        return [dict(r) for r in db.q("SELECT * FROM deliveries ORDER BY id DESC LIMIT ?", (max(1, min(limit, 200)),))]

    @app.get("/api/rules", tags=["events"])
    def list_rules():
        return [dict(r) for r in db.q("""SELECT r.*, p.name AS profile_name FROM notify_rules r
                                         LEFT JOIN profiles p ON p.id=r.profile_id ORDER BY r.id""")]

    def rule_check(body):
        if body.profile_id is not None:
            get_profile(body.profile_id)

    @app.post("/api/rules", tags=["events"], status_code=201, dependencies=[Depends(require_key)])
    def create_rule(body: RuleIn):
        rule_check(body)
        rid = db.q("INSERT INTO notify_rules(profile_id, trigger, enabled) VALUES(?,?,?)",
                   (body.profile_id, body.trigger, int(body.enabled))).lastrowid
        return dict(db.q("SELECT * FROM notify_rules WHERE id=?", (rid,)).fetchone())

    @app.put("/api/rules/{rid}", tags=["events"], dependencies=[Depends(require_key)])
    def update_rule(rid: int, body: RuleIn):
        rule_check(body)
        if db.q("UPDATE notify_rules SET profile_id=?, trigger=?, enabled=? WHERE id=?",
                (body.profile_id, body.trigger, int(body.enabled), rid)).rowcount == 0:
            raise HTTPException(404, "rule not found")
        return dict(db.q("SELECT * FROM notify_rules WHERE id=?", (rid,)).fetchone())

    @app.delete("/api/rules/{rid}", tags=["events"], status_code=204, dependencies=[Depends(require_key)])
    def delete_rule(rid: int):
        if db.q("DELETE FROM notify_rules WHERE id=?", (rid,)).rowcount == 0:
            raise HTTPException(404, "rule not found")

    @app.get("/api/profiles/{pid}/events", tags=["profiles"])
    def profile_events(pid: int, limit: int = 50):
        """Profile-level arrive/leave transitions (debounced across devices), newest first."""
        get_profile(pid)
        return [dict(r) for r in db.q("SELECT kind, ts FROM profile_events WHERE profile_id=? ORDER BY id DESC LIMIT ?",
                                      (pid, max(1, min(limit, 500))))]

    return app

