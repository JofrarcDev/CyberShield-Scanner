"""Reglas de análisis: versiones obsoletas/vulnerables y servicios expuestos.

La base es deliberadamente pequeña y editable. Es una heurística basada en banners:
verifica siempre manualmente cada hallazgo (los banners pueden ser falsos u ocultar
parches retroportados por la distribución).
"""
from __future__ import annotations

import re

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}


def vtuple(version: str) -> tuple[int, ...]:
    """'7.4p1' -> (7, 4, 1); '2.4.49' -> (2, 4, 49)."""
    return tuple(int(x) for x in re.findall(r"\d+", version or ""))


# key: subcadena (minúsculas) del nombre del producto.
# Condición: "exact" (lista), "below" (versión) o "range" (desde, hasta-excluido).
VERSION_RULES = [
    dict(key="openssh", range=((8, 5), (9, 8)), sev="high",
         title="OpenSSH vulnerable a regreSSHion (ejecución remota sin autenticar)",
         cve="CVE-2024-6387", advice="Actualiza a OpenSSH 9.8p1 o superior."),
    dict(key="openssh", below=(8, 0), sev="medium",
         title="OpenSSH obsoleto (sin soporte)", cve="",
         advice="Actualiza a una versión mantenida de OpenSSH."),
    dict(key="apache", exact=[(2, 4, 49)], sev="critical",
         title="Apache 2.4.49: path traversal y posible RCE",
         cve="CVE-2021-41773", advice="Actualiza Apache httpd inmediatamente."),
    dict(key="apache", exact=[(2, 4, 50)], sev="critical",
         title="Apache 2.4.50: corrección incompleta de path traversal / RCE",
         cve="CVE-2021-42013", advice="Actualiza Apache httpd inmediatamente."),
    dict(key="apache", below=(2, 4, 58), sev="medium",
         title="Apache httpd obsoleto con vulnerabilidades públicas conocidas", cve="",
         advice="Actualiza a la última versión estable 2.4.x."),
    dict(key="nginx", below=(1, 24), sev="medium",
         title="nginx obsoleto (rama sin soporte)", cve="",
         advice="Actualiza a una versión estable vigente de nginx."),
    dict(key="iis", below=(10, 0), sev="high",
         title="IIS anterior a 10.0 (Windows Server sin soporte)", cve="",
         advice="Migra a una versión de Windows Server con soporte."),
    dict(key="php", below=(8, 2), sev="medium",
         title="PHP sin soporte de seguridad (fin de vida)", cve="",
         advice="Actualiza a una rama de PHP con soporte activo."),
    dict(key="vsftpd", exact=[(2, 3, 4)], sev="critical",
         title="vsftpd 2.3.4 con puerta trasera conocida",
         cve="CVE-2011-2523", advice="Reemplaza el binario y reinstala desde una fuente confiable."),
    dict(key="proftpd", below=(1, 3, 8), sev="medium",
         title="ProFTPD obsoleto", cve="",
         advice="Actualiza a ProFTPD 1.3.8 o superior."),
    dict(key="mysql", below=(8, 0), sev="medium",
         title="MySQL 5.x o anterior (fin de vida)", cve="",
         advice="Migra a MySQL 8.0+ con soporte."),
    dict(key="mariadb", below=(10, 11), sev="medium",
         title="MariaDB sin soporte", cve="",
         advice="Actualiza a MariaDB 10.11 LTS o superior."),
]

# Servicios que no deberían estar expuestos a redes no confiables.
PORT_RULES = {
    21: ("medium", "FTP expuesto (tráfico sin cifrar)", "Usa SFTP/FTPS y limita el acceso por firewall."),
    23: ("high", "Telnet expuesto (credenciales en texto plano)", "Desactiva Telnet y usa SSH."),
    111: ("low", "rpcbind expuesto", "Filtra el puerto 111 si no es necesario."),
    135: ("medium", "MSRPC expuesto", "Bloquea RPC en el perímetro."),
    139: ("medium", "NetBIOS/SMB expuesto", "Bloquea SMB en el perímetro."),
    445: ("medium", "SMB expuesto", "Bloquea SMB en el perímetro y deshabilita SMBv1."),
    1433: ("medium", "Microsoft SQL Server expuesto", "Restringe el acceso a redes de administración."),
    3306: ("medium", "Base de datos MySQL expuesta", "Escucha solo en localhost o en una red interna."),
    3389: ("medium", "RDP expuesto", "Usa VPN o pasarela RDP con MFA; habilita NLA."),
    5432: ("medium", "Base de datos PostgreSQL expuesta", "Restringe con pg_hba.conf y firewall."),
    5900: ("medium", "VNC expuesto", "Túnel por VPN/SSH y contraseña robusta."),
    6379: ("high", "Redis expuesto", "Enlaza a localhost, activa autenticación y firewall."),
    9200: ("high", "Elasticsearch expuesto", "Activa seguridad nativa y restringe la red."),
    11211: ("high", "Memcached expuesto (abuso por amplificación)", "Enlaza a localhost y filtra el puerto."),
    27017: ("high", "MongoDB expuesto", "Activa autenticación y restringe la red."),
}


def _match(rule: dict, ver: tuple[int, ...]) -> bool:
    if not ver:
        return False
    if "exact" in rule:
        return ver in rule["exact"]
    if "below" in rule:
        return ver < rule["below"]
    lo, hi = rule["range"]
    return lo <= ver < hi


def _finding(r, severity, title, category, detail, advice, cve=""):
    return {
        "host": r.host, "ip": r.ip, "port": r.port, "severity": severity,
        "title": title, "category": category, "cve": cve,
        "detail": detail, "advice": advice,
    }


def analyze(results) -> list[dict]:
    findings: list[dict] = []
    for r in results:
        if r.port in PORT_RULES:
            sev, title, advice = PORT_RULES[r.port]
            findings.append(_finding(r, sev, title, "exposición",
                                     f"Puerto {r.port}/tcp abierto ({r.service}).", advice))
        for comp in r.components:
            ver = vtuple(comp["version"])
            for rule in VERSION_RULES:
                if rule["key"] in comp["product"].lower() and _match(rule, ver):
                    findings.append(_finding(
                        r, rule["sev"], rule["title"], "versión",
                        f"Detectado {comp['product']} {comp['version']} en {r.port}/tcp.",
                        rule["advice"], rule["cve"]))
        if r.service == "redis" and "+PONG" in r.banner:
            findings.append(_finding(
                r, "critical", "Redis responde sin autenticación", "configuración",
                "El servidor respondió PONG a un PING sin credenciales.",
                "Configura requirepass/ACL y no lo expongas a la red."))
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f["severity"]], f["ip"], f["port"]))
    return findings


def risk_score(findings: list[dict]) -> int:
    return min(100, sum(SEV_WEIGHT[f["severity"]] for f in findings))
