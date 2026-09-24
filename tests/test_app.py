import time
import pytest
from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app
from app import scanner

FOUND = {}


def fake_scan(settings):
    return dict(FOUND)


@pytest.fixture
def client(tmp_path):
    FOUND.clear()
    s = Settings(db_path=str(tmp_path / "t.db"), scanner_enabled=False, present_timeout=300)
    app = create_app(s, scan_fn=fake_scan)
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
