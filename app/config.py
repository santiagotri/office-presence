import os
from dataclasses import dataclass, field


def _env(name, default):
    return os.environ.get(name, default)


@dataclass
class Settings:
    db_path: str = field(default_factory=lambda: _env("OP_DB_PATH", "presence.db"))
    scan_interval: int = field(default_factory=lambda: int(_env("OP_SCAN_INTERVAL", "30")))
    present_timeout: int = field(default_factory=lambda: int(_env("OP_PRESENT_TIMEOUT", "300")))
    subnet: str = field(default_factory=lambda: _env("OP_SUBNET", ""))  # e.g. 192.168.1.0/24
    ping_sweep: bool = field(default_factory=lambda: _env("OP_PING_SWEEP", "1") == "1")
    use_scapy: bool = field(default_factory=lambda: _env("OP_USE_SCAPY", "0") == "1")
    api_key: str = field(default_factory=lambda: _env("OP_API_KEY", ""))
    scanner_enabled: bool = field(default_factory=lambda: _env("OP_SCANNER", "1") == "1")
