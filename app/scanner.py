"""Network presence scanner: reads the ARP/neighbor table (Linux + macOS)."""
import ipaddress
import logging
import platform
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger("scanner")
MAC_RE = re.compile(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})")


def normalize_mac(mac: str) -> str:
    """'A:b:0C:1:2:3' / 'ab-0c-..' / 'ab0c01020304' -> 'ab:0c:01:02:03:04'."""
    m = mac.strip().lower().replace("-", ":").replace(".", "")
    if ":" in m:
        parts = m.split(":")
    else:
        parts = [m[i:i + 2] for i in range(0, len(m), 2)]
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9a-f]{1,2}", p) for p in parts):
        raise ValueError(f"invalid MAC: {mac!r}")
    return ":".join(p.zfill(2) for p in parts)


def _valid(mac: str) -> bool:
    return mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") and not mac.startswith("01:00:5e")


def parse_ip_neigh(out: str) -> dict[str, str]:
    res = {}
    for line in out.splitlines():
        if "lladdr" not in line or "FAILED" in line or "INCOMPLETE" in line:
            continue
        ip = line.split()[0]
        m = MAC_RE.search(line.split("lladdr", 1)[1])
        if m:
            mac = normalize_mac(m.group(1))
            if _valid(mac):
                res[mac] = ip
    return res


def parse_arp_an(out: str) -> dict[str, str]:
    res = {}
    for line in out.splitlines():
        if "incomplete" in line:
            continue
        ipm = re.search(r"\(([\d.]+)\)", line)
        m = MAC_RE.search(line.split(" at ", 1)[-1]) if " at " in line else None
        if ipm and m:
            mac = normalize_mac(m.group(1))
            if _valid(mac):
                res[mac] = ipm.group(1)
    return res


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except Exception as e:  # noqa: BLE001
        log.warning("cmd %s failed: %s", cmd, e)
        return ""


def read_neighbors() -> dict[str, str]:
    if platform.system() == "Linux" and shutil.which("ip"):
        return parse_ip_neigh(_run(["ip", "neigh", "show"]))
    return parse_arp_an(_run(["arp", "-an"]))


def ping_sweep(subnet: str, workers: int = 64):
    net = ipaddress.ip_network(subnet, strict=False)
    if net.num_addresses > 1024:
        log.warning("subnet %s too large for ping sweep, skipping", subnet)
        return
    mac_os = platform.system() == "Darwin"
    def ping(ip):
        cmd = ["ping", "-c", "1", "-t" if mac_os else "-W", "1", str(ip)]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
    with ThreadPoolExecutor(workers) as ex:
        list(ex.map(lambda ip: _safe(ping, ip), net.hosts()))


def _safe(fn, *a):
    try:
        fn(*a)
    except Exception:  # noqa: BLE001
        pass


def scapy_scan(subnet: str) -> dict[str, str]:
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore
    except ImportError:
        return {}
    try:
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=2, verbose=0)
        return {normalize_mac(r.hwsrc): r.psrc for _, r in ans}
    except Exception as e:  # noqa: BLE001  (usually: not root)
        log.warning("scapy scan failed: %s", e)
        return {}


def scan(settings) -> dict[str, str]:
    """Return {mac: ip} of devices currently visible."""
    found = {}
    if settings.subnet and settings.use_scapy:
        found.update(scapy_scan(settings.subnet))
    if settings.subnet and settings.ping_sweep:
        ping_sweep(settings.subnet)
    found.update(read_neighbors())
    return found
