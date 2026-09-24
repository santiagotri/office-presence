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
"""


class DB:
    def __init__(self, path):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self.lock = threading.Lock()

    def q(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur

    def record(self, found: dict, now=None):
        now = now or time.time()
        for mac, ip in found.items():
            self.q("""INSERT INTO sightings(mac, ip, first_seen, last_seen) VALUES(?,?,?,?)
                      ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, last_seen=excluded.last_seen""",
                   (mac, ip, now, now))
