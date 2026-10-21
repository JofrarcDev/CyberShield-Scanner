"""Motor de escaneo: sockets TCP multihilo, banner grabbing e integración opcional con Nmap."""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
    1433, 1723, 3306, 3389, 5432, 5900, 6379, 8000, 8008, 8080, 8443, 8888, 9200,
    11211, 27017,
]
HTTP_PORTS = {80, 8000, 8008, 8080, 8888}
HTTPS_PORTS = {443, 8443}
TLS_PASSIVE = {465, 636, 993, 995}
ACTIVE_PROBES = {6379: b"PING\r\n", 11211: b"version\r\n"}
MAX_HOSTS = 256


@dataclass
class Target:
    label: str  # lo que escribió el usuario (host o IP)
    ip: str


@dataclass
class PortResult:
    host: str
    ip: str
    port: int
    service: str = "unknown"
    banner: str = ""
    components: list = field(default_factory=list)  # [{"product": str, "version": str}]
    source: str = "socket"


# (regex, servicio, producto). Si el patrón tiene un grupo, es la versión.
SIGNATURES = [
    (r"SSH-\d\.\d+-OpenSSH_([\w.]+)", "ssh", "OpenSSH"),
    (r"^SSH-\d", "ssh", None),
    (r"^HTTP/\d", "http", None),
    (r"^Server:\s*Apache(?:/([\d.]+))?", "http", "Apache httpd"),
    (r"^Server:\s*nginx(?:/([\d.]+))?", "http", "nginx"),
    (r"^Server:\s*Microsoft-IIS/([\d.]+)", "http", "Microsoft IIS"),
    (r"^X-Powered-By:\s*PHP/([\d.]+)", "http", "PHP"),
    (r"vsFTPd ([\d.]+)", "ftp", "vsftpd"),
    (r"ProFTPD ([\d.]+\w*)", "ftp", "ProFTPD"),
    (r"Pure-FTPd", "ftp", "Pure-FTPd"),
    (r"^220[ -].*\bFTP\b", "ftp", None),
    (r"Postfix", "smtp", "Postfix"),
    (r"Exim ([\d.]+)", "smtp", "Exim"),
    (r"^220[ -].*\bSMTP\b", "smtp", None),
    (r"Dovecot", "imap", "Dovecot"),
    (r"^\+PONG|^-NOAUTH|^-DENIED", "redis", "Redis"),
    (r"^VERSION ([\d.]+)", "memcached", "Memcached"),
]


def parse_ports(spec: str) -> list[int]:
    """'top', 'all' o listas/rangos como '22,80,8000-8100'."""
    spec = spec.strip().lower()
    if spec == "top":
        return list(TOP_PORTS)
    if spec == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    try:
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = (int(x) for x in part.split("-", 1))
                if a > b:
                    a, b = b, a
                ports.update(range(a, b + 1))
            else:
                ports.add(int(part))
    except ValueError:
        raise ValueError(f"Especificación de puertos inválida: '{spec}'") from None
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Los puertos deben estar entre 1 y 65535")
    return sorted(ports)


def expand_targets(raw: list[str]) -> list[Target]:
    """Acepta IPs, hostnames y rangos CIDR (máx. 256 hosts)."""
    out: list[Target] = []
    seen: set[str] = set()
    for item in raw:
        item = item.strip()
        pairs: list[tuple[str, str]]
        if "/" in item:
            net = ipaddress.ip_network(item, strict=False)
            hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
            if len(hosts) > MAX_HOSTS:
                raise ValueError(f"{item} contiene {len(hosts)} hosts (máximo {MAX_HOSTS})")
            pairs = [(str(h), str(h)) for h in hosts]
        else:
            try:
                pairs = [(item, str(ipaddress.ip_address(item)))]
            except ValueError:
                try:
                    pairs = [(item, socket.gethostbyname(item))]
                except socket.gaierror:
                    raise ValueError(f"No se pudo resolver el host: {item}") from None
        for label, ip in pairs:
            if ip not in seen:
                seen.add(ip)
                out.append(Target(label, ip))
    return out


# ---------------------------------------------------------------- sockets ----
def _clean(raw: bytes) -> str:
    text = raw.decode("latin-1", errors="ignore")
    text = re.sub(r"[^\x20-\x7e\r\n]", " ", text)
    return re.sub(r"[ \t]+", " ", text).strip()[:512]


def grab_banner(sock: socket.socket, label: str, port: int, timeout: float) -> str:
    """Lee el banner del servicio; envía una sonda mínima solo donde es necesario."""
    sock.settimeout(timeout)
    conn = sock
    try:
        if port in HTTPS_PORTS or port in TLS_PASSIVE:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(sock, server_hostname=label)
        if port in HTTP_PORTS or port in HTTPS_PORTS:
            req = f"HEAD / HTTP/1.0\r\nHost: {label}\r\nUser-Agent: CyberShield/1.0\r\n\r\n"
            conn.sendall(req.encode())
        elif port in ACTIVE_PROBES:
            conn.sendall(ACTIVE_PROBES[port])
        return _clean(conn.recv(2048))
    except (OSError, ssl.SSLError):
        return ""
    finally:
        try:
            conn.close()
        except OSError:
            pass


def identify(port: int, banner: str) -> tuple[str, list[dict]]:
    """Deduce servicio y componentes (producto/versión) a partir del banner."""
    service, components = "", []
    for pattern, svc, product in SIGNATURES:
        m = re.search(pattern, banner, re.I | re.M)
        if not m:
            continue
        service = service or svc
        if product:
            version = m.group(1) if m.groups() and m.group(1) else ""
            components.append({"product": product, "version": version})

    low = banner.lower()
    if port == 3306 or "mysql_native_password" in low or "mariadb" in low:
        if "mariadb" in low:
            m = re.search(r"(\d+\.\d+\.\d+)-MariaDB", banner, re.I)
            components.append({"product": "MariaDB", "version": m.group(1) if m else ""})
            service = "mysql"
        elif port == 3306 or "mysql" in low:
            m = re.search(r"\d+\.\d+\.\d+", banner)
            if m:
                components.append({"product": "MySQL", "version": m.group(0)})
                service = "mysql"

    if not service:
        try:
            service = socket.getservbyport(port, "tcp")
        except OSError:
            service = "unknown"
    return service, components


def probe_port(target: Target, port: int, timeout: float, grab: bool) -> Optional[PortResult]:
    try:
        sock = socket.create_connection((target.ip, port), timeout=timeout)
    except OSError:
        return None  # cerrado, filtrado o inalcanzable
    with sock:
        banner = grab_banner(sock, target.label, port, timeout) if grab else ""
    service, components = identify(port, banner)
    return PortResult(target.label, target.ip, port, service, banner, components)


def scan(
    targets: list[Target],
    ports: list[int],
    threads: int = 100,
    timeout: float = 1.0,
    grab: bool = True,
    progress: Optional[Callable[[int, int], None]] = None,
) -> tuple[list[PortResult], bool]:
    """Escaneo TCP connect multihilo. Devuelve (resultados, interrumpido)."""
    total = len(targets) * len(ports)
    results: list[PortResult] = []
    done, interrupted = 0, False
    ex = ThreadPoolExecutor(max_workers=max(1, threads), thread_name_prefix="scan")
    try:
        futures = [ex.submit(probe_port, t, p, timeout, grab) for t in targets for p in ports]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                results.append(res)
            done += 1
            if progress and (done % 25 == 0 or done == total):
                progress(done, total)
    except KeyboardInterrupt:
        interrupted = True
        ex.shutdown(wait=False, cancel_futures=True)
    else:
        ex.shutdown(wait=True)
    results.sort(key=lambda r: (r.ip, r.port))
    return results, interrupted


# ------------------------------------------------------------------- nmap ----
class NmapUnavailable(RuntimeError):
    pass


def enrich_with_nmap(results: list[PortResult], timeout: int = 180) -> None:
    """Refina servicio/versión con `nmap -sV`, solo sobre los puertos ya abiertos."""
    try:
        import nmap  # python-nmap
    except ImportError:
        raise NmapUnavailable("Falta python-nmap: pip install python-nmap") from None
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        raise NmapUnavailable("No se encontró el binario de nmap en el PATH") from None

    by_ip: dict[str, list[PortResult]] = {}
    for r in results:
        by_ip.setdefault(r.ip, []).append(r)

    for ip, rows in by_ip.items():
        port_list = ",".join(str(r.port) for r in rows)
        try:
            nm.scan(hosts=ip, ports=port_list, arguments="-sV --version-light -Pn", timeout=timeout)
        except (nmap.PortScannerError, nmap.PortScannerTimeout) as exc:
            raise NmapUnavailable(f"Nmap falló en {ip}: {exc}") from None
        if ip not in nm.all_hosts():
            continue
        tcp = nm[ip].get("tcp", {})
        for r in rows:
            info = tcp.get(r.port)
            if not info or info.get("state") != "open":
                continue
            if info.get("name"):
                r.service = info["name"]
            product = (info.get("product") or "").strip()
            version = (info.get("version") or "").strip().split(" ")[0]
            if product:
                r.components = [c for c in r.components if c["product"].lower() != product.lower()]
                r.components.insert(0, {"product": product, "version": version})
            r.source = "socket+nmap"


def now() -> float:
    return time.time()
