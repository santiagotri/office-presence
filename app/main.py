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


class DiscoverIn(BaseModel):
    subnet: str = Field("", examples=["192.168.1.0/24"], description="Empty = OP_SUBNET or auto-detect")


def create_app(settings: Optional[Settings] = None, scan_fn=None, discover_fn=None) -> FastAPI:
    settings = settings or Settings()
    scan_fn = scan_fn or scanner.scan
    discover_fn = discover_fn or scanner.discover
    db = DB(settings.db_path)
    state = {"last_scan": None, "last_error": None}

    def do_scan():
        try:
            db.record(scan_fn(settings), timeout=settings.present_timeout)
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
    app.state.db, app.state.settings, app.state.do_scan = db, settings, do_scan

    def require_key(x_api_key: Optional[str] = Header(None)):
        if settings.api_key and x_api_key != settings.api_key:
            raise HTTPException(401, "invalid or missing X-API-Key")

    def device_info(mac, now, limit=0):
        s, events = db.history(mac, limit) if limit else (
            db.q("SELECT * FROM sightings WHERE mac=?", (mac,)).fetchone(), [])
        last = s["last_seen"] if s else None
        present = bool(last and now - last <= settings.present_timeout)
        out = {"ip": s["ip"] if s else None, "first_seen": s["first_seen"] if s else None,
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
        db.q("INSERT OR REPLACE INTO devices(mac, profile_id, label) VALUES(?,?,?)", (d.mac, pid, d.label))

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
        db.record({d["mac"]: d["ip"] for d in res["devices"]}, timeout=settings.present_timeout)
        owners = {r["mac"]: (r["profile_id"], r["name"], r["label"]) for r in db.q(
            "SELECT d.mac, d.profile_id, d.label, p.name FROM devices d JOIN profiles p ON p.id=d.profile_id")}
        for d in res["devices"]:
            o = owners.get(d["mac"])
            d["profile_id"], d["profile_name"], d["label"] = o if o else (None, None, "")
            d["first_seen"] = db.q("SELECT first_seen FROM sightings WHERE mac=?", (d["mac"],)).fetchone()[0]
        return {"timestamp": time.time(), **res}

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
        rows = db.q("""SELECT s.mac, s.ip, s.first_seen, s.last_seen FROM sightings s
                       LEFT JOIN devices d ON d.mac=s.mac WHERE d.mac IS NULL AND s.last_seen>=?
                       ORDER BY s.last_seen DESC""", (cutoff,))
        return [dict(r) for r in rows]

    return app

