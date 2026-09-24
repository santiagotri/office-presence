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


def create_app(settings: Optional[Settings] = None, scan_fn=None) -> FastAPI:
    settings = settings or Settings()
    scan_fn = scan_fn or scanner.scan
    db = DB(settings.db_path)
    state = {"last_scan": None, "last_error": None}

    def do_scan():
        try:
            db.record(scan_fn(settings))
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

    def seen(mac):
        r = db.q("SELECT ip, last_seen FROM sightings WHERE mac=?", (mac,)).fetchone()
        return (r["ip"], r["last_seen"]) if r else (None, None)

    def profile_out(p):
        now = time.time()
        devs = []
        for d in db.q("SELECT mac, label FROM devices WHERE profile_id=? ORDER BY mac", (p["id"],)):
            ip, last = seen(d["mac"])
            devs.append({"mac": d["mac"], "label": d["label"], "ip": ip, "last_seen": last,
                         "present": bool(last and now - last <= settings.present_timeout)})
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

