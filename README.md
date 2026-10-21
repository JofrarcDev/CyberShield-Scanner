# CyberShield Scanner CLI

Escáner automatizado de vulnerabilidades en Python: escaneo TCP multihilo con sockets,
detección de versiones obsoletas por banner, integración opcional con Nmap y reportes
interactivos en HTML y JSON.

> **Uso autorizado únicamente.** Escanea solo sistemas propios o con permiso escrito.
> La herramienta exige `--authorized` (o confirmación interactiva) antes de ejecutar.

## Instalación

```bash
python -m venv .venv && source .venv/bin/activate
pip install .            # sin dependencias obligatorias
pip install ".[nmap]"    # opcional: python-nmap (instala también el binario nmap)
```

## Uso

```bash
python -m cybershield 192.168.1.10 --authorized
python -m cybershield scanme.nmap.org -p 1-1024 -t 200 --nmap --authorized
python -m cybershield 10.0.0.0/28 -p 22,80,443,8000-8100 -f json --authorized
python -m cybershield 10.0.0.5 --fail-on high --authorized   # exit 2 si hay >= high (CI/CD)
```

| Opción | Descripción |
|---|---|
| `-p, --ports` | `top` (defecto), `all` o rangos `22,80,8000-8100` |
| `-t, --threads` | Hilos concurrentes (100) |
| `--timeout` | Timeout por conexión en segundos (1.0) |
| `--nmap` | Refina servicio/versión con `nmap -sV` sobre los puertos abiertos |
| `--no-banner` | Solo detecta puertos abiertos |
| `-f, --format` | `html`, `json` o `both` |
| `-o, --output` | Directorio de salida (`reports/`) |
| `--fail-on` | Código de salida 2 si hay hallazgos de esa severidad o mayor |

## Arquitectura

```
cybershield/
  scanner.py   sockets + ThreadPoolExecutor, banner grabbing, firmas, nmap (python-nmap)
  vulndb.py    reglas de versiones obsoletas/vulnerables y servicios expuestos, score de riesgo
  report.py    JSON estructurado y HTML autocontenido (filtros, búsqueda, orden, tema claro/oscuro)
  cli.py       argparse, progreso, resumen en consola, códigos de salida
```

## Añadir reglas

Edita `VERSION_RULES` en `vulndb.py`:

```python
dict(key="nginx", below=(1, 24), sev="medium", title="nginx obsoleto", cve="", advice="Actualiza nginx.")
```
Condiciones: `exact=[(2,4,49)]`, `below=(1,24)` o `range=((8,5),(9,8))`.

## Limitaciones

- Las versiones salen de banners: pueden estar ocultas, falsificadas o parcheadas (backports).
- La base de reglas es pequeña; complementa con Nmap NSE, OpenVAS o Nuclei.
- Escaneo TCP connect (no SYN): es visible en logs y más lento que nmap -sS.
- Los hallazgos son indicios: verifícalos manualmente.
