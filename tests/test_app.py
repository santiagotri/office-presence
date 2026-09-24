import time
import pytest
from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app
from app import scanner

FOUND = {}


def fake_scan(settings):
    return dict(FOUND)


def fake_discover(settings, subnet=""):
    return {"subnet": subnet or "10.0.0.0/24",
            "devices": [{"mac": m, "ip": ip, "hostname": "", "private_mac": scanner.is_private_mac(m)}
                        for m, ip in FOUND.items()]}


@pytest.fixture
def client(tmp_path):
    FOUND.clear()
    s = Settings(db_path=str(tmp_path / "t.db"), scanner_enabled=False, present_timeout=300)
    app = create_app(s, scan_fn=fake_scan, discover_fn=fake_discover)
    with TestClient(app) as c:
        c.app_ref = app
        yield c


def test_normalize():
    assert scanner.normalize_mac("A:B:C:D:E:F") == "0a:0b:0c:0d:0e:0f"
    assert scanner.normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert scanner.normalize_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"
    with pytest.raises(ValueError):
        scanner.normalize_mac("nope")


def test_parsers():
    linux = ("192.168.1.10 dev wlan0 lladdr AA:BB:CC:DD:EE:01 REACHABLE\n"
             "192.168.1.11 dev wlan0  FAILED\n192.168.1.12 dev wlan0 lladdr aa:bb:cc:dd:ee:02 STALE\n")
    assert scanner.parse_ip_neigh(linux) == {"aa:bb:cc:dd:ee:01": "192.168.1.10", "aa:bb:cc:dd:ee:02": "192.168.1.12"}
    mac = ("? (192.168.1.10) at a:bb:cc:dd:ee:1 on en0 ifscope [ethernet]\n"
           "? (192.168.1.11) at (incomplete) on en0 ifscope [ethernet]\n"
           "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n")
    assert scanner.parse_arp_an(mac) == {"0a:bb:cc:dd:ee:01": "192.168.1.10"}


def test_flow(client):
    r = client.post("/api/profiles", json={"name": "Ana", "devices": [{"mac": "AA-BB-CC-DD-EE-01", "label": "phone"}]})
    assert r.status_code == 201
    pid = r.json()["id"]
    assert client.get("/api/presence").json()["present"] == []
    FOUND.update({"aa:bb:cc:dd:ee:01": "10.0.0.5", "aa:bb:cc:dd:ee:99": "10.0.0.9"})
    client.app_ref.state.do_scan()
    p = client.get("/api/presence").json()
    assert [x["name"] for x in p["present"]] == ["Ana"]
    assert [d["mac"] for d in client.get("/api/devices/unknown").json()] == ["aa:bb:cc:dd:ee:99"]
    assert client.post(f"/api/profiles/{pid}/devices", json={"mac": "aa:bb:cc:dd:ee:99", "label": "laptop"}).status_code == 201
    assert client.get("/api/devices/unknown").json() == []
    assert client.delete(f"/api/profiles/{pid}/devices/AA:BB:CC:DD:EE:99").status_code == 204
    assert client.put(f"/api/profiles/{pid}", json={"name": "Ana M"}).json()["name"] == "Ana M"
    assert client.delete(f"/api/profiles/{pid}").status_code == 204
    assert client.get(f"/api/profiles/{pid}").status_code == 404


def test_timeout(client):
    pid = client.post("/api/profiles", json={"name": "Bo", "devices": [{"mac": "aa:bb:cc:dd:ee:02"}]}).json()["id"]
    client.app_ref.state.db.record({"aa:bb:cc:dd:ee:02": "10.0.0.2"}, now=time.time() - 301)
    assert client.get(f"/api/profiles/{pid}").json()["present"] is False


def test_duplicate_mac_conflict(client):
    client.post("/api/profiles", json={"name": "A", "devices": [{"mac": "aa:bb:cc:dd:ee:03"}]})
    r = client.post("/api/profiles", json={"name": "B", "devices": [{"mac": "aa:bb:cc:dd:ee:03"}]})
    assert r.status_code == 409
    assert [p["name"] for p in client.get("/api/profiles").json()] == ["A"]


def test_api_key(tmp_path):
    s = Settings(db_path=str(tmp_path / "k.db"), scanner_enabled=False, api_key="s3cret")
    with TestClient(create_app(s, scan_fn=fake_scan)) as c:
        assert c.post("/api/profiles", json={"name": "X"}).status_code == 401
        assert c.post("/api/profiles", json={"name": "X"}, headers={"X-API-Key": "s3cret"}).status_code == 201
        assert c.get("/api/presence").status_code == 200
        assert c.get("/health").json()["auth_required"] is True


def test_discover_and_assign(client):
    pid = client.post("/api/profiles", json={"name": "Cy"}).json()["id"]
    FOUND.update({"a8:bb:cc:dd:ee:10": "10.0.0.10", "da:bb:cc:dd:ee:11": "10.0.0.11"})
    r = client.post("/api/discover").json()
    assert r["subnet"] == "10.0.0.0/24"
    devs = {d["mac"]: d for d in r["devices"]}
    assert devs["da:bb:cc:dd:ee:11"]["private_mac"] and not devs["a8:bb:cc:dd:ee:10"]["private_mac"]
    assert devs["a8:bb:cc:dd:ee:10"]["profile_id"] is None and devs["a8:bb:cc:dd:ee:10"]["first_seen"]
    client.post(f"/api/profiles/{pid}/devices", json={"mac": "a8:bb:cc:dd:ee:10", "label": "phone"})
    r = client.post("/api/discover", json={"subnet": "10.0.0.0/24"}).json()
    d = next(x for x in r["devices"] if x["mac"] == "a8:bb:cc:dd:ee:10")
    assert (d["profile_id"], d["profile_name"], d["label"]) == (pid, "Cy", "phone")
    assert client.get(f"/api/profiles/{pid}").json()["present"] is True


def test_history(client):
    db, mac, t0 = client.app_ref.state.db, "aa:bb:cc:dd:ee:20", time.time() - 10000
    db.record({mac: "10.0.0.20"}, now=t0, timeout=300)
    db.record({mac: "10.0.0.20"}, now=t0 + 100, timeout=300)   # still here: no new event
    db.record({}, now=t0 + 1000, timeout=300)                   # gone -> depart at last sighting
    db.record({mac: "10.0.0.21"}, now=t0 + 5000, timeout=300)  # back -> arrive
    h = client.get(f"/api/devices/{mac.upper()}/history").json()
    assert [(e["kind"], round(e["ts"] - t0)) for e in h["events"]] == [("arrive", 5000), ("depart", 100), ("arrive", 0)]
    assert round(h["first_seen"] - t0) == 0 and h["present"] is False and h["arrived_at"] is None
    db.record({mac: "10.0.0.21"}, timeout=300)
    h = client.get(f"/api/devices/{mac}/history").json()
    assert h["present"] is True and h["arrived_at"] == pytest.approx(time.time(), abs=5)  # gap > timeout = new visit
    assert h["events"][0]["kind"] == "arrive" and len(h["events"]) == 5


def test_name_unassigned_device(client):
    mac = "aa:bb:cc:dd:ee:77"
    FOUND[mac] = "10.0.0.77"
    client.post("/api/scan")
    r = client.put("/api/devices/AA-BB-CC-DD-EE-77/name", json={"name": " Printer "})
    assert r.status_code == 200 and r.json() == {"mac": mac, "name": "Printer"}
    u = client.get("/api/devices/unknown").json()
    assert [(d["mac"], d["name"]) for d in u] == [(mac, "Printer")]
    assert client.post("/api/discover").json()["devices"][0]["name"] == "Printer"
    assert client.get(f"/api/devices/{mac}/history").json()["name"] == "Printer"
    # still assignable later, keeps its name (and uses it as default label)
    pid = client.post("/api/profiles", json={"name": "Office"}).json()["id"]
    dev = client.post(f"/api/profiles/{pid}/devices", json={"mac": mac}).json()["devices"][0]
    assert dev["name"] == "Printer" and dev["label"] == "Printer"
    assert client.get("/api/devices/unknown").json() == []
    client.delete(f"/api/profiles/{pid}/devices/{mac}")
    assert client.get("/api/devices/unknown").json()[0]["name"] == "Printer"
    # clear
    assert client.put(f"/api/devices/{mac}/name", json={"name": ""}).json()["name"] == ""
    assert client.get("/api/devices/unknown").json()[0]["name"] == ""
    assert client.put("/api/devices/nope/name", json={"name": "x"}).status_code == 422


def test_aliases_migration(tmp_path):
    import sqlite3
    p = tmp_path / "old.db"
    c = sqlite3.connect(p)
    c.executescript("CREATE TABLE profiles (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE);"
                    "CREATE TABLE sightings (mac TEXT PRIMARY KEY, ip TEXT, first_seen REAL NOT NULL, last_seen REAL NOT NULL);")
    c.close()
    app = create_app(Settings(db_path=str(p), scanner_enabled=False), scan_fn=fake_scan, discover_fn=fake_discover)
    with TestClient(app) as cl:
        assert cl.put("/api/devices/aa:bb:cc:dd:ee:01/name", json={"name": "x"}).status_code == 200


def test_delete_unknown_device(client):
    mac = "aa:bb:cc:dd:ee:88"
    FOUND[mac] = "10.0.0.88"
    client.post("/api/scan")
    client.put(f"/api/devices/{mac}/name", json={"name": "Toaster"})
    assert client.delete("/api/devices/AA-BB-CC-DD-EE-88").status_code == 204
    assert client.get("/api/devices/unknown").json() == []
    assert client.get(f"/api/devices/{mac}/history").status_code == 404
    assert client.delete(f"/api/devices/{mac}").status_code == 404
    assert client.delete("/api/devices/nope").status_code == 422
    # reappears fresh on next scan
    client.post("/api/scan")
    u = client.get("/api/devices/unknown").json()
    assert [(d["mac"], d["name"]) for d in u] == [(mac, "")]
    assert [e["kind"] for e in client.get(f"/api/devices/{mac}/history").json()["events"]] == ["arrive"]
    # assigned devices are protected
    pid = client.post("/api/profiles", json={"name": "Ana", "devices": [{"mac": mac}]}).json()["id"]
    assert client.delete(f"/api/devices/{mac}").status_code == 409
    assert client.get(f"/api/profiles/{pid}").json()["devices"][0]["first_seen"]


def test_ignore_device(client):
    mac, other = "aa:bb:cc:dd:ee:99", "aa:bb:cc:dd:ee:98"
    FOUND.update({mac: "10.0.0.99", other: "10.0.0.98"})
    client.post("/api/scan")
    client.put(f"/api/devices/{mac}/name", json={"name": "TV"})
    assert client.delete(f"/api/devices/{mac}?ignore=true").status_code == 204
    ig = client.get("/api/devices/ignored").json()
    assert [(d["mac"], d["name"]) for d in ig] == [(mac, "TV")]
    client.post("/api/scan")
    assert [d["mac"] for d in client.get("/api/devices/unknown").json()] == [other]
    assert [d["mac"] for d in client.post("/api/discover").json()["devices"]] == [other]
    assert client.get(f"/api/devices/{mac}/history").status_code == 404
    # un-ignore: seen again on next scan
    assert client.delete(f"/api/devices/ignored/{mac}").status_code == 204
    assert client.delete(f"/api/devices/ignored/{mac}").status_code == 404
    client.post("/api/scan")
    assert {d["mac"] for d in client.get("/api/devices/unknown").json()} == {mac, other}
    # ignoring a never-seen MAC is allowed
    assert client.delete("/api/devices/aa:bb:cc:dd:ee:00?ignore=true").status_code == 204


def test_ignored_migration(tmp_path):
    import sqlite3
    p = tmp_path / "old.db"
    c = sqlite3.connect(p)
    c.executescript("CREATE TABLE profiles (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE);"
                    "CREATE TABLE sightings (mac TEXT PRIMARY KEY, ip TEXT, first_seen REAL NOT NULL, last_seen REAL NOT NULL);"
                    "INSERT INTO sightings VALUES('aa:bb:cc:dd:ee:01','10.0.0.1',1,1);")
    c.close()
    app = create_app(Settings(db_path=str(p), scanner_enabled=False), scan_fn=fake_scan, discover_fn=fake_discover)
    with TestClient(app) as cl:
        assert cl.delete("/api/devices/aa:bb:cc:dd:ee:01?ignore=true").status_code == 204
        assert cl.get("/api/devices/ignored").json()[0]["mac"] == "aa:bb:cc:dd:ee:01"


# ---- OpenClaw events ----
import json as _json
import threading as _th
from http.server import BaseHTTPRequestHandler, HTTPServer


@pytest.fixture
def hook():
    got = {"reqs": [], "codes": []}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = _json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            got["reqs"].append({"path": self.path, "auth": self.headers.get("Authorization"),
                                "idem": self.headers.get("Idempotency-Key"), "body": body})
            code = got["codes"].pop(0) if got["codes"] else 200
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true,"runId":"r1"}')

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    _th.Thread(target=srv.serve_forever, daemon=True).start()
    got["url"] = f"http://127.0.0.1:{srv.server_port}/hooks/agent"
    yield got
    srv.shutdown()


def _wait(c):
    c.app_ref.state.notifier.q.join()


def _setup(client, hook, trigger="both", pid=None):
    client.app_ref.state.notifier.backoff = 0
    client.put("/api/integrations/openclaw", json={"enabled": True, "url": hook["url"], "token": "s3cret-token-xyz"})
    client.post("/api/rules", json={"profile_id": pid, "trigger": trigger})


def test_openclaw_config_masks_token(client, hook, monkeypatch):
    r = client.put("/api/integrations/openclaw", json={"enabled": True, "url": hook["url"], "token": "abcdefghijkl"}).json()
    assert "token" not in r and r["token_set"] and r["token_masked"] == "abc…jkl" and r["token_source"] == "db"
    r = client.put("/api/integrations/openclaw", json={"enabled": True, "url": hook["url"]}).json()
    assert r["token_set"]  # omitted token keeps the stored one
    monkeypatch.setenv("OP_OPENCLAW_TOKEN", "fromenv-123456")
    assert client.get("/api/integrations/openclaw").json()["token_source"] == "env"
    client.post("/api/integrations/openclaw/test")
    assert hook["reqs"][-1]["auth"] == "Bearer fromenv-123456"
    assert client.put("/api/integrations/openclaw", json={"url": hook["url"], "channel": "telegram"}).status_code == 422


def test_profile_events_debounced_and_pushed(client, hook):
    pid = client.post("/api/profiles", json={"name": "Ana", "devices": [
        {"mac": "aa:bb:cc:dd:ee:01"}, {"mac": "aa:bb:cc:dd:ee:02"}]}).json()["id"]
    _setup(client, hook)
    app = client.app_ref
    app.state.do_scan()  # initialises state silently (absent)
    FOUND["aa:bb:cc:dd:ee:01"] = "10.0.0.5"
    app.state.do_scan()
    FOUND["aa:bb:cc:dd:ee:02"] = "10.0.0.6"  # second device: no new profile event
    app.state.do_scan()
    _wait(client)
    assert len(hook["reqs"]) == 1
    req = hook["reqs"][0]
    assert req["path"] == "/hooks/agent" and req["auth"] == "Bearer s3cret-token-xyz" and req["idem"]
    assert req["body"]["name"] == "office-presence" and "channel" not in req["body"]
    assert req["body"]["message"].startswith("Ana llegó a la oficina")
    data = _json.loads(req["body"]["message"].split("[office-presence]\n", 1)[1])
    assert data["event"] == "arrive" and data["profile"] == "Ana" and len(data["devices"]) == 2
    # both devices gone past the timeout -> one leave
    db = app.state.db
    db.q("UPDATE sightings SET last_seen=last_seen-1000")
    FOUND.clear()
    app.state.do_scan()
    _wait(client)
    assert len(hook["reqs"]) == 2 and "salió de la oficina" in hook["reqs"][1]["body"]["message"]
    ev = client.get(f"/api/profiles/{pid}/events").json()
    assert [e["kind"] for e in ev] == ["leave", "arrive"]
    d = client.get("/api/integrations/openclaw/deliveries").json()
    assert len(d) == 2 and all(x["ok"] for x in d)


def test_rules_filter(client, hook):
    a = client.post("/api/profiles", json={"name": "Ana", "devices": [{"mac": "aa:bb:cc:dd:ee:01"}]}).json()["id"]
    client.post("/api/profiles", json={"name": "Bo", "devices": [{"mac": "aa:bb:cc:dd:ee:02"}]})
    _setup(client, hook, trigger="leave", pid=a)
    app = client.app_ref
    app.state.do_scan()
    FOUND.update({"aa:bb:cc:dd:ee:01": "1", "aa:bb:cc:dd:ee:02": "2"})
    app.state.do_scan()
    _wait(client)
    assert hook["reqs"] == []  # arrivals don't match a leave-only rule
    app.state.db.q("UPDATE sightings SET last_seen=last_seen-1000")
    FOUND.clear()
    app.state.do_scan()
    _wait(client)
    assert len(hook["reqs"]) == 1 and hook["reqs"][0]["body"]["message"].startswith("Ana salió")
    rid = client.get("/api/rules").json()[0]["id"]
    client.put(f"/api/rules/{rid}", json={"profile_id": a, "trigger": "both", "enabled": False})
    FOUND["aa:bb:cc:dd:ee:01"] = "1"
    app.state.do_scan()
    _wait(client)
    assert len(hook["reqs"]) == 1  # disabled rule


def test_retry_and_failure_log(client, hook):
    _setup(client, hook)
    hook["codes"] = [503, 200]
    r = client.post("/api/integrations/openclaw/test").json()
    assert r["ok"] and r["delivery"]["attempts"] == 2
    hook["codes"] = [401]
    r = client.post("/api/integrations/openclaw/test").json()
    assert not r["ok"] and r["delivery"]["attempts"] == 1 and r["delivery"]["http_status"] == 401
    client.put("/api/integrations/openclaw", json={"enabled": True, "url": "http://127.0.0.1:9/hooks/agent"})
    r = client.post("/api/integrations/openclaw/test").json()
    assert not r["ok"] and r["delivery"]["http_status"] is None and r["delivery"]["attempts"] == 3


def test_scanner_never_blocks_on_hook(client):
    import time as _t
    pid = client.post("/api/profiles", json={"name": "Ana", "devices": [{"mac": "aa:bb:cc:dd:ee:01"}]}).json()["id"]
    client.put("/api/integrations/openclaw", json={"enabled": True, "url": "http://10.255.255.1:18789/hooks/agent"})
    client.post("/api/rules", json={"profile_id": pid, "trigger": "both"})
    app = client.app_ref
    app.state.do_scan()
    FOUND["aa:bb:cc:dd:ee:01"] = "1"
    t0 = _t.time()
    app.state.do_scan()
    assert _t.time() - t0 < 1
