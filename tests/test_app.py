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
