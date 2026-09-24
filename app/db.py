import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS devices (
  mac TEXT PRIMARY KEY, profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  label TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS aliases (
  mac TEXT PRIMARY KEY, name TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sightings (
  mac TEXT PRIMARY KEY, ip TEXT, first_seen REAL NOT NULL, last_seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT NOT NULL, kind TEXT NOT NULL, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS ignored (
  mac TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', ignored_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS profile_state (
  profile_id INTEGER PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE, present INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS profile_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  kind TEXT NOT NULL, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS integrations (name TEXT PRIMARY KEY, config TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS notify_rules (
  id INTEGER PRIMARY KEY AUTOINCREMENT, profile_id INTEGER REFERENCES profiles(id) ON DELETE CASCADE,
  trigger TEXT NOT NULL DEFAULT 'both', enabled INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS deliveries (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, event TEXT NOT NULL, profile TEXT NOT NULL,
  message TEXT NOT NULL, ok INTEGER NOT NULL, http_status INTEGER, error TEXT, attempts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS events_mac_ts ON events(mac, ts);
"""


class DB:
    def __init__(self, path):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        cols = {r[1] for r in self.conn.execute("PRAGMA table_info(sightings)")}
        for col, ddl in (("present", "INTEGER NOT NULL DEFAULT 0"), ("arrived_at", "REAL")):
            if col not in cols:  # migrate DBs created before history existed
                self.conn.execute(f"ALTER TABLE sightings ADD COLUMN {col} {ddl}")
        self.conn.commit()
        self.lock = threading.Lock()

    def q(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur

    def record(self, found: dict, now=None, timeout=None):
        """Store sightings and derive arrival/departure events.

        A MAC *arrives* when seen while not marked present (first sighting, or after being gone
        longer than `timeout`). It *departs* when not seen for more than `timeout`; the departure
        is stamped at its last sighting."""
        now = now or time.time()
        skip = self.ignored_macs()
        for mac, ip in found.items():
            if mac in skip:
                continue
            r = self.q("SELECT last_seen, present FROM sightings WHERE mac=?", (mac,)).fetchone()
            if r and r["present"] and timeout and now - r["last_seen"] > timeout:
                self.q("INSERT INTO events(mac, kind, ts) VALUES(?, 'depart', ?)", (mac, r["last_seen"]))
                r = {"present": 0}
            if not r or not r["present"]:
                self.q("INSERT INTO events(mac, kind, ts) VALUES(?, 'arrive', ?)", (mac, now))
                self.q("""INSERT INTO sightings(mac, ip, first_seen, last_seen, present, arrived_at)
                          VALUES(?,?,?,?,1,?) ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip,
                          last_seen=excluded.last_seen, present=1, arrived_at=excluded.arrived_at""",
                       (mac, ip, now, now, now))
            else:
                self.q("UPDATE sightings SET ip=?, last_seen=? WHERE mac=?", (ip, now, mac))
        if timeout:
            for r in self.q("SELECT mac, last_seen FROM sightings WHERE present=1 AND last_seen<?",
                            (now - timeout,)).fetchall():
                self.q("INSERT INTO events(mac, kind, ts) VALUES(?, 'depart', ?)", (r["mac"], r["last_seen"]))
                self.q("UPDATE sightings SET present=0 WHERE mac=?", (r["mac"],))

    def profile_transitions(self, now=None):
        """Compare each profile's presence (any device present) with its stored state.
        Returns [{profile_id, profile, event: arrive|leave, ts, devices}] for real transitions only.
        A profile with no stored state (new, or pre-migration DB) is initialised silently."""
        now = now or time.time()
        out = []
        rows = self.q("""SELECT p.id, p.name, ps.present AS was,
                   COALESCE(MAX(s.present), 0) AS now_present, MAX(s.last_seen) AS last
                   FROM profiles p LEFT JOIN profile_state ps ON ps.profile_id=p.id
                   LEFT JOIN devices d ON d.profile_id=p.id LEFT JOIN sightings s ON s.mac=d.mac
                   GROUP BY p.id""").fetchall()
        for r in rows:
            cur = int(r["now_present"] or 0)
            if r["was"] is None:
                self.q("INSERT INTO profile_state(profile_id, present) VALUES(?,?)", (r["id"], cur))
                continue
            if cur == r["was"]:
                continue
            kind = "arrive" if cur else "leave"
            ts = now if cur else (r["last"] or now)
            self.q("UPDATE profile_state SET present=? WHERE profile_id=?", (cur, r["id"]))
            self.q("INSERT INTO profile_events(profile_id, kind, ts) VALUES(?,?,?)", (r["id"], kind, ts))
            devs = [dict(d) for d in self.q(
                """SELECT d.mac, d.label, COALESCE(s.present,0) AS present, s.ip FROM devices d
                   LEFT JOIN sightings s ON s.mac=d.mac WHERE d.profile_id=? ORDER BY d.mac""", (r["id"],))]
            out.append({"profile_id": r["id"], "profile": r["name"], "event": kind, "ts": ts, "devices": devs})
        return out

    def integration(self, name):
        import json
        r = self.q("SELECT config FROM integrations WHERE name=?", (name,)).fetchone()
        return json.loads(r[0]) if r else {}

    def set_integration(self, name, cfg):
        import json
        self.q("INSERT INTO integrations(name, config) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET config=excluded.config",
               (name, json.dumps(cfg)))

    def ignored_macs(self):
        return {r[0] for r in self.q("SELECT mac FROM ignored")}

    def forget(self, mac):
        """Drop everything recorded about a MAC (sightings, events, alias)."""
        n = self.q("DELETE FROM sightings WHERE mac=?", (mac,)).rowcount
        n += self.q("DELETE FROM events WHERE mac=?", (mac,)).rowcount
        n += self.q("DELETE FROM aliases WHERE mac=?", (mac,)).rowcount
        return n

    def history(self, mac, limit=20):
        s = self.q("SELECT * FROM sightings WHERE mac=?", (mac,)).fetchone()
        ev = self.q("SELECT kind, ts FROM events WHERE mac=? ORDER BY ts DESC, id DESC LIMIT ?", (mac, limit))
        return (dict(s) if s else None), [dict(e) for e in ev]
