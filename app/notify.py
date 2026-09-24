"""Push profile arrival/departure events to OpenClaw (Gateway inbound webhook /hooks/agent).

Delivery runs on a daemon worker thread fed by a queue, so the scanner never blocks on HTTP."""
import json
import logging
import os
import queue
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime

log = logging.getLogger("notify")
DEFAULT_URL = "http://127.0.0.1:18789/hooks/agent"
KIND_ES = {"arrive": "llegó a la oficina", "leave": "salió de la oficina"}


def _fmt_time(ts):
    return datetime.fromtimestamp(ts).strftime("%H:%M")


def build_payload(cfg, ev):
    """ev = {profile, profile_id, event: arrive|leave|test, ts, devices: [..]}"""
    if ev["event"] == "test":
        text = "Prueba de office-presence: la integración con OpenClaw funciona."
    else:
        text = f"{ev['profile']} {KIND_ES[ev['event']]} ({_fmt_time(ev['ts'])})."
    data = {"source": "office-presence", "event": ev["event"], "profile": ev["profile"],
            "profile_id": ev.get("profile_id"), "time": datetime.fromtimestamp(ev["ts"]).astimezone().isoformat(),
            "ts": ev["ts"], "devices": ev.get("devices", [])}
    body = {"message": f"{text}\n\n[office-presence]\n{json.dumps(data, ensure_ascii=False)}",
            "name": "office-presence"}
    for k, f in (("agent_id", "agentId"), ("channel", "channel"), ("to", "to")):
        if cfg.get(k):
            body[f] = cfg[k]
    if not (cfg.get("channel") and cfg.get("to")):
        body.pop("channel", None), body.pop("to", None)  # OpenClaw rejects half destinations
    return body, text


class Notifier:
    def __init__(self, db, timeout=5.0, retries=3, backoff=1.0):
        self.db, self.timeout, self.retries, self.backoff = db, timeout, retries, backoff
        self.q = queue.Queue()
        self.t = threading.Thread(target=self._run, daemon=True, name="openclaw-notify")
        self.t.start()

    def config(self):
        c = self.db.integration("openclaw")
        c.setdefault("url", DEFAULT_URL)
        env = os.environ.get("OP_OPENCLAW_TOKEN")
        c["token_source"] = "env" if env else ("db" if c.get("token") else "none")
        if env:
            c["token"] = env
        return c

    def matches(self, cfg, ev):
        if not cfg.get("enabled") or not cfg.get("url"):
            return False
        for r in self.db.q("SELECT * FROM notify_rules WHERE enabled=1"):
            if r["profile_id"] not in (None, ev["profile_id"]):
                continue
            if r["trigger"] in ("both", ev["event"]):
                return True
        return False

    def submit(self, ev, force=False):
        cfg = self.config()
        if force or self.matches(cfg, ev):
            self.q.put((cfg, ev))
            return True
        return False

    def _run(self):
        while True:
            cfg, ev = self.q.get()
            try:
                self.deliver(cfg, ev)
            except Exception:  # noqa: BLE001
                log.exception("delivery crashed")
            finally:
                self.q.task_done()

    def deliver(self, cfg, ev):
        body, text = build_payload(cfg, ev)
        key = f"op-{ev['event']}-{ev.get('profile_id')}-{int(ev['ts'])}-{uuid.uuid4().hex[:6]}"
        hdr = {"Content-Type": "application/json", "Idempotency-Key": key}
        if cfg.get("token"):
            hdr["Authorization"] = f"Bearer {cfg['token']}"
        status, err, attempt = None, "", 0
        for attempt in range(1, self.retries + 1):
            req = urllib.request.Request(cfg["url"], json.dumps(body).encode(), hdr, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    status, err = r.status, ""
                    break
            except urllib.error.HTTPError as e:
                status, err = e.code, e.read()[:300].decode("utf-8", "replace")
                if e.code < 500 and e.code != 429:
                    break  # auth / validation errors won't fix themselves
            except Exception as e:  # noqa: BLE001
                status, err = None, str(e)[:300]
            time.sleep(self.backoff * attempt)
        ok = status is not None and 200 <= status < 300
        self.db.q("""INSERT INTO deliveries(ts, event, profile, message, ok, http_status, error, attempts)
                     VALUES(?,?,?,?,?,?,?,?)""",
                  (time.time(), ev["event"], ev["profile"], text, int(ok), status, err, attempt))
        self.db.q("DELETE FROM deliveries WHERE id NOT IN (SELECT id FROM deliveries ORDER BY id DESC LIMIT 200)")
        return ok
