"""CLI de CyberShield Scanner."""
from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from pathlib import Path

from . import __version__
from .report import build_report, write_html, write_json
from .scanner import NmapUnavailable, enrich_with_nmap, expand_targets, parse_ports, scan
from .vulndb import SEVERITIES, analyze

USE_COLOR = sys.stdout.isatty()
COLORS = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "37", "bold": "1", "dim": "2"}

BANNER = r"""
   ____      _               ____  _     _      _     _
  / ___|   _| |__   ___ _ __/ ___|| |__ (_) ___| | __| |
 | |  | | | | '_ \ / _ \ '__\___ \| '_ \| |/ _ \ |/ _` |
 | |__| |_| | |_) |  __/ |   ___) | | | | |  __/ | (_| |
  \____\__, |_.__/ \___|_|  |____/|_| |_|_|\___|_|\__,_|
       |___/   Scanner CLI v{v}
"""


def c(text: str, style: str) -> str:
    return f"\033[{COLORS[style]}m{text}\033[0m" if USE_COLOR else text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cybershield",
        description="Escáner de puertos y versiones obsoletas con reportes HTML/JSON. "
                    "Úsalo solo en sistemas propios o con autorización escrita.",
        epilog="Ejemplos:\n  cybershield 192.168.1.10 --authorized\n"
               "  cybershield scanme.nmap.org -p 1-1024 -t 200 --nmap --authorized\n"
               "  cybershield 10.0.0.0/28 -p top -f json --fail-on high --authorized",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("targets", nargs="+", help="IPs, hostnames o CIDR (máx. 256 hosts)")
    p.add_argument("-p", "--ports", default="top",
                   help="'top' (por defecto), 'all' o lista/rangos: 22,80,8000-8100")
    p.add_argument("-t", "--threads", type=int, default=100, help="hilos concurrentes (100)")
    p.add_argument("--timeout", type=float, default=1.0, help="timeout por conexión en segundos (1.0)")
    p.add_argument("--nmap", action="store_true", help="refina versiones con nmap -sV (requiere nmap + python-nmap)")
    p.add_argument("--no-banner", action="store_true", help="solo detecta puertos abiertos, sin leer banners")
    p.add_argument("-o", "--output", default="reports", help="directorio de salida (reports)")
    p.add_argument("-f", "--format", choices=["html", "json", "both"], default="both")
    p.add_argument("--name", default="", help="prefijo del nombre de archivo")
    p.add_argument("--fail-on", choices=SEVERITIES[:4], help="código de salida 2 si hay hallazgos >= severidad (CI/CD)")
    p.add_argument("--authorized", action="store_true", help="confirma que tienes autorización para escanear")
    p.add_argument("-q", "--quiet", action="store_true", help="salida mínima")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def confirm_authorization(args) -> bool:
    if args.authorized:
        return True
    if not sys.stdin.isatty():
        print("Error: agrega --authorized para confirmar que tienes permiso de escanear estos objetivos.", file=sys.stderr)
        return False
    ans = input("¿Tienes autorización explícita para escanear estos objetivos? [s/N] ").strip().lower()
    return ans in {"s", "si", "sí", "y", "yes"}


def progress_printer(done: int, total: int) -> None:
    if not sys.stderr.isatty():
        return
    pct = done * 100 // total
    bar = "#" * (pct // 4)
    print(f"\r  escaneando [{bar:<25}] {pct:3d}%  ({done}/{total})", end="", file=sys.stderr, flush=True)
    if done == total:
        print(file=sys.stderr)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not args.quiet:
        print(c(BANNER.format(v=__version__), "bold"))
    if not confirm_authorization(args):
        return 1
    if args.threads < 1 or args.timeout <= 0:
        print("Error: --threads debe ser >= 1 y --timeout > 0", file=sys.stderr)
        return 1

    try:
        targets = expand_targets(args.targets)
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"Objetivos: {len(targets)} host(s) | Puertos: {len(ports)} | Hilos: {args.threads}")

    started = time.time()
    results, interrupted = scan(
        targets, ports, args.threads, args.timeout,
        grab=not args.no_banner, progress=None if args.quiet else progress_printer,
    )
    if interrupted:
        print(c("\nEscaneo interrumpido: se guardarán resultados parciales.", "medium"), file=sys.stderr)

    if args.nmap and results:
        try:
            if not args.quiet:
                print("Refinando versiones con nmap…")
            enrich_with_nmap(results)
        except NmapUnavailable as exc:
            print(c(f"Aviso: {exc}. Se continúa solo con sockets.", "medium"), file=sys.stderr)

    findings = analyze(results)
    duration = round(time.time() - started, 2)
    meta = {"threads": args.threads, "timeout_s": args.timeout, "duration_s": duration,
            "nmap": bool(args.nmap), "interrupted": interrupted}
    report = build_report(targets, ports, results, findings, meta)

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"{args.name + '-' if args.name else ''}cybershield-{stamp}"
    written = []
    if args.format in ("json", "both"):
        written.append(write_json(report, out / f"{base}.json"))
    if args.format in ("html", "both"):
        written.append(write_html(report, out / f"{base}.html"))

    print_summary(report, results, findings, written, args.quiet)

    if args.fail_on:
        limit = SEVERITIES.index(args.fail_on)
        if any(SEVERITIES.index(f["severity"]) <= limit for f in findings):
            return 2
    return 130 if interrupted else 0


def print_summary(report, results, findings, written, quiet: bool) -> None:
    s = report["summary"]
    if not quiet:
        print()
        for r in results:
            prod = ", ".join(f"{x['product']} {x['version']}".strip() for x in r.components) or "-"
            print(f"  {r.host:<20} {r.port:>5}/tcp  {r.service:<12} {prod}")
        if findings:
            print(c("\nHallazgos:", "bold"))
            for f in findings:
                tag = c(f"[{f['severity'].upper():^8}]", f["severity"])
                cve = f" ({f['cve']})" if f["cve"] else ""
                print(f"  {tag} {f['host']}:{f['port']} {f['title']}{cve}")
    counts = ", ".join(f"{k}={v}" for k, v in s["by_severity"].items() if v) or "ninguno"
    print(f"\n{s['open_ports']} puerto(s) abierto(s) | {s['findings']} hallazgo(s): {counts} | "
          f"riesgo máx. {s['max_risk_score']}/100")
    for path in written:
        print(f"  -> {path}")


if __name__ == "__main__":
    sys.exit(main())
