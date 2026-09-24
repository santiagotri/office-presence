import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS devices (
  mac TEXT PRIMARY KEY, profile_id INTEGER NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  label TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS sightings (
  mac TEXT PRIMARY KEY, ip TEXT, first_seen REAL NOT NULL, last_seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, mac TEXT NOT NULL, kind TEXT NOT NULL, ts REAL NOT NULL);
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
        for mac, ip in found.items():
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

    def history(self, mac, limit=20):
        s = self.q("SELECT * FROM sightings WHERE mac=?", (mac,)).fetchone()
        ev = self.q("SELECT kind, ts FROM events WHERE mac=? ORDER BY ts DESC, id DESC LIMIT ?", (mac, limit))
        return (dict(s) if s else None), [dict(e) for e in ev]
