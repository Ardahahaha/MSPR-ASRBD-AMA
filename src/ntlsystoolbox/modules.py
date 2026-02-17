# modules.py
# NTL-SysToolbox (MSPR ASRBD) — 3 modules : Diagnostic / Sauvegarde WMS / Audit d’obsolescence
# Contrainte utilisateur : seulement 2 fichiers Python (cli.py + modules.py)

from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timezone, date
from html import escape as html_escape
from pathlib import Path
from typing import Any, Iterable
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


# =========================
# Codes supervision (Nagios-like)
# =========================
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3


# =========================
# Dépendances optionnelles (pour éviter crash si pas installées)
# =========================
try:
    import psutil  # type: ignore
except Exception:
    psutil = None  # type: ignore

try:
    import pymysql  # type: ignore
except Exception:
    pymysql = None  # type: ignore


# =========================
# Config par défaut (Annexe C)
# =========================
DEFAULT_CONFIG: dict[str, Any] = {
    "reports_dir": "reports",
    "diagnostic": {
        "ad_controllers": ["192.168.10.10", "192.168.10.11"],  # DC01/DC02
        "ad_ports": [53, 88, 389],  # DNS/Kerberos/LDAP (TCP)
        "timeout_sec": 2.0,
        "mysql": {
            "host": "192.168.10.21",  # WMS-DB
            "port": 3306,
            "user": "wms_read",
            "database": "wms",
            "password_env": "NTL_MYSQL_PASSWORD",
        },
    },
    "backup": {
        "mysql": {
            "host": "192.168.10.21",
            "port": 3306,
            "user": "wms_backup",
            "database": "wms",
            "password_env": "NTL_MYSQL_PASSWORD",
        },
        "mysqldump_path": "mysqldump",
        "timeout_sec": 30.0,
        "default_table": "orders",
    },
    "audit": {
        "default_scan_cidr": "192.168.10.0/24",
        "scan_ports": [22, 80, 135, 445, 3389, 3306],
        "eol_api_base": "https://endoflife.date/api",
        "soon_days": 180,
        "timeout_sec": 1.0,
    },
}


# =========================
# Helpers généraux
# =========================
def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ts_utc_compact() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def _write_json(path: Path, payload: Any) -> None:
    _ensure_dir(path.parent)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    _ensure_dir(path.parent)
    path.write_text(text, encoding="utf-8")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def _env(name: str, default: str | None = None) -> str | None:
    v = os.getenv(name)
    return v if v not in (None, "") else default


def _comma_list(s: str) -> list[str]:
    return [x.strip() for x in s.split(",") if x.strip()]


def _get_password(mysql_cfg: dict[str, Any]) -> str:
    # priorité : password explicite > password_env
    if mysql_cfg.get("password"):
        return str(mysql_cfg["password"])
    env_name = mysql_cfg.get("password_env")
    if env_name:
        return os.getenv(str(env_name), "")
    return ""


def load_config(path: str | None = None) -> dict[str, Any]:
    """
    Charge la configuration depuis un fichier simple :
    - JSON (sans dépendance) recommandé si tu veux zéro lib.
    - YAML supporté si PyYAML est installé (sinon erreur claire).
    Surcharge possible via variables d’environnement.
    """
    cfg_path = Path(path or _env("NTL_CONFIG", "config/config.json") or "config/config.json")
    user_cfg: dict[str, Any] = {}

    if cfg_path.exists():
        if cfg_path.suffix.lower() in (".json",):
            user_cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        elif cfg_path.suffix.lower() in (".yml", ".yaml"):
            try:
                import yaml  # type: ignore
            except Exception as e:
                raise RuntimeError(
                    "Config YAML détectée mais PyYAML n'est pas installé. "
                    "Installe PyYAML ou utilise config.json."
                ) from e
            user_cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        else:
            raise RuntimeError("Format config non supporté. Utilise .json (ou .yml/.yaml avec PyYAML).")

    cfg = _deep_merge(DEFAULT_CONFIG, user_cfg)

    # Surcharges env (exemples)
    if _env("NTL_REPORTS_DIR"):
        cfg["reports_dir"] = _env("NTL_REPORTS_DIR")

    if _env("NTL_AD_CONTROLLERS"):
        cfg["diagnostic"]["ad_controllers"] = _comma_list(_env("NTL_AD_CONTROLLERS") or "")

    if _env("NTL_AD_PORTS"):
        cfg["diagnostic"]["ad_ports"] = [int(x) for x in _comma_list(_env("NTL_AD_PORTS") or "")]

    if _env("NTL_MYSQL_HOST"):
        cfg["diagnostic"]["mysql"]["host"] = _env("NTL_MYSQL_HOST")
        cfg["backup"]["mysql"]["host"] = _env("NTL_MYSQL_HOST")

    if _env("NTL_MYSQL_PORT"):
        p = int(_env("NTL_MYSQL_PORT") or "3306")
        cfg["diagnostic"]["mysql"]["port"] = p
        cfg["backup"]["mysql"]["port"] = p

    if _env("NTL_SCAN_CIDR"):
        cfg["audit"]["default_scan_cidr"] = _env("NTL_SCAN_CIDR")

    return cfg


def _tcp_check(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _ping(host: str, timeout_sec: int = 1) -> bool:
    exe = shutil.which("ping")
    if not exe:
        return False
    sysname = platform.system().lower()
    try:
        if "windows" in sysname:
            # -n 1 one packet, -w timeout(ms)
            r = subprocess.run(
                [exe, "-n", "1", "-w", str(timeout_sec * 1000), host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            # -c 1 one packet, -W timeout(sec) (Linux)
            r = subprocess.run(
                [exe, "-c", "1", "-W", str(timeout_sec), host],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        return r.returncode == 0
    except OSError:
        return False


def _system_snapshot() -> dict[str, Any]:
    """
    État synthétique du serveur local.
    Conforme au CDC : si exécuté sur Windows Server -> infos Windows,
    si exécuté sur Ubuntu -> infos Ubuntu.
    """
    info: dict[str, Any] = {
        "collected_at_utc": _now_utc_iso(),
        "hostname": socket.gethostname(),
        "os": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
    }

    if psutil is None:
        info["warning"] = "psutil non installé -> uptime/cpu/ram/disk indisponibles"
        return info

    try:
        uptime = int(time.time() - psutil.boot_time())
    except Exception:
        uptime = 0

    disks: list[dict[str, Any]] = []
    try:
        for part in psutil.disk_partitions(all=False):
            try:
                usage = psutil.disk_usage(part.mountpoint)
                disks.append(
                    {
                        "device": part.device,
                        "mount": part.mountpoint,
                        "fstype": part.fstype,
                        "used_percent": round(usage.percent, 2),
                        "total_gb": round(usage.total / (1024**3), 2),
                        "free_gb": round(usage.free / (1024**3), 2),
                    }
                )
            except Exception:
                continue
    except Exception:
        disks = []

    info.update(
        {
            "uptime_seconds": uptime,
            "cpu": {
                "logical_count": psutil.cpu_count(logical=True),
                "percent": psutil.cpu_percent(interval=0.6),
            },
            "ram": {
                "total_gb": round(psutil.virtual_memory().total / (1024**3), 2),
                "used_percent": round(psutil.virtual_memory().percent, 2),
            },
            "disks": disks,
        }
    )
    return info


def _worst(a: int, b: int) -> int:
    return a if a >= b else b


# =========================
# Module 1 — Diagnostic
# =========================
def run_diagnostic(cfg: dict[str, Any]) -> dict[str, Any]:
    ts = _ts_utc_compact()
    reports_dir = Path(cfg["reports_dir"]) / "diagnostic"
    out_json = reports_dir / f"{ts}_diagnostic.json"

    timeout = float(cfg["diagnostic"].get("timeout_sec", 2.0))
    dcs: list[str] = list(cfg["diagnostic"].get("ad_controllers", []))
    ports: list[int] = [int(p) for p in cfg["diagnostic"].get("ad_ports", [53, 88, 389])]

    mysql_cfg = dict(cfg["diagnostic"].get("mysql", {}))
    mysql_password = _get_password(mysql_cfg)

    payload: dict[str, Any] = {
        "module": "diagnostic",
        "timestamp_utc": ts,
        "checks": {
            "ad_dns": [],
            "mysql": {},
            "system_snapshot": {},
        },
    }

    code = OK

    # AD/DNS checks
    for dc in dcs:
        item = {"host": dc, "ping": False, "ports": {}, "status": "OK"}
        item["ping"] = _ping(dc, timeout_sec=max(1, int(timeout)))
        for p in ports:
            item["ports"][str(p)] = _tcp_check(dc, int(p), timeout)

        ok_ports = all(item["ports"].values()) if item["ports"] else False
        if not item["ping"] or not ok_ports:
            item["status"] = "CRITICAL"
            code = _worst(code, CRITICAL)

        payload["checks"]["ad_dns"].append(item)

    # MySQL check
    mysql_result: dict[str, Any] = {
        "host": mysql_cfg.get("host"),
        "port": int(mysql_cfg.get("port", 3306)),
        "user": mysql_cfg.get("user"),
        "database": mysql_cfg.get("database"),
        "status": "UNKNOWN",
    }

    if pymysql is None:
        mysql_result["status"] = "UNKNOWN"
        mysql_result["error"] = "PyMySQL non installé (pip install PyMySQL)."
        code = _worst(code, UNKNOWN)
    else:
        try:
            if not mysql_password:
                raise RuntimeError("Mot de passe MySQL absent (utilise NTL_MYSQL_PASSWORD).")
            conn = pymysql.connect(
                host=str(mysql_cfg.get("host")),
                port=int(mysql_cfg.get("port", 3306)),
                user=str(mysql_cfg.get("user")),
                password=mysql_password,
                database=str(mysql_cfg.get("database")),
                connect_timeout=max(1, int(timeout)),
                read_timeout=max(1, int(timeout)),
                write_timeout=max(1, int(timeout)),
            )
            with conn.cursor() as cur:
                cur.execute("SELECT 1;")
                cur.fetchone()
                cur.execute("SELECT VERSION();")
                mysql_result["version"] = cur.fetchone()[0]
            conn.close()
            mysql_result["status"] = "OK"
        except Exception as e:
            mysql_result["status"] = "CRITICAL"
            mysql_result["error"] = str(e)
            code = _worst(code, CRITICAL)

    payload["checks"]["mysql"] = mysql_result

    # System snapshot (local machine)
    try:
        payload["checks"]["system_snapshot"] = _system_snapshot()
    except Exception as e:
        payload["checks"]["system_snapshot"] = {"error": str(e)}
        code = _worst(code, WARNING)

    _write_json(out_json, payload)

    summary = "DIAGNOSTIC OK"
    if code == WARNING:
        summary = "DIAGNOSTIC WARNING"
    elif code == CRITICAL:
        summary = "DIAGNOSTIC CRITICAL"
    elif code == UNKNOWN:
        summary = "DIAGNOSTIC UNKNOWN"

    return {
        "code": code,
        "summary": summary,
        "artifacts": [str(out_json)],
        "data": payload,
    }


# =========================
# Module 2 — Sauvegarde WMS
# =========================
def _mysqldump_available(path_hint: str) -> str | None:
    return shutil.which(path_hint) or shutil.which("mysqldump")


def run_backup(cfg: dict[str, Any], table: str | None = None) -> dict[str, Any]:
    ts = _ts_utc_compact()
    base_dir = Path(cfg["reports_dir"]) / "backup"
    out_sql = base_dir / "sql" / f"{ts}_wms_dump.sql"
    out_csv = base_dir / "csv" / f"{ts}_{(table or cfg['backup'].get('default_table','table'))}.csv"
    out_json = base_dir / f"{ts}_backup_manifest.json"

    mysql_cfg = dict(cfg["backup"].get("mysql", {}))
    mysql_password = _get_password(mysql_cfg)
    timeout = float(cfg["backup"].get("timeout_sec", 30.0))
    dump_path_hint = str(cfg["backup"].get("mysqldump_path", "mysqldump"))
    export_table = table or str(cfg["backup"].get("default_table", "orders"))

    code = OK
    payload: dict[str, Any] = {
        "module": "backup",
        "timestamp_utc": ts,
        "mysql": {
            "host": mysql_cfg.get("host"),
            "port": int(mysql_cfg.get("port", 3306)),
            "user": mysql_cfg.get("user"),
            "database": mysql_cfg.get("database"),
        },
        "artifacts": {},
    }

    # 2.1 SQL dump via mysqldump (standard)
    try:
        if not mysql_password:
            raise RuntimeError("Mot de passe MySQL absent (utilise NTL_MYSQL_PASSWORD).")

        exe = _mysqldump_available(dump_path_hint)
        if not exe:
            raise RuntimeError("mysqldump introuvable (installe client MySQL ou configure mysqldump_path).")

        env = os.environ.copy()
        env["MYSQL_PWD"] = mysql_password  # évite d’afficher le mdp en argument

        cmd = [
            exe,
            "-h",
            str(mysql_cfg.get("host")),
            "-P",
            str(int(mysql_cfg.get("port", 3306))),
            "-u",
            str(mysql_cfg.get("user")),
            "--single-transaction",
            "--routines",
            "--events",
            str(mysql_cfg.get("database")),
        ]
        r = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=max(5, int(timeout)),
        )
        if r.returncode != 0:
            raise RuntimeError(r.stderr.decode(errors="ignore")[:500])

        _ensure_dir(out_sql.parent)
        out_sql.write_bytes(r.stdout)

        payload["artifacts"]["sql_dump"] = {
            "path": str(out_sql),
            "sha256": _sha256_file(out_sql),
        }
    except Exception as e:
        code = _worst(code, CRITICAL)
        payload["artifacts"]["sql_dump_error"] = str(e)

    # 2.2 Export table CSV
    try:
        if pymysql is None:
            raise RuntimeError("PyMySQL non installé (pip install PyMySQL).")
        if not mysql_password:
            raise RuntimeError("Mot de passe MySQL absent (utilise NTL_MYSQL_PASSWORD).")

        conn = pymysql.connect(
            host=str(mysql_cfg.get("host")),
            port=int(mysql_cfg.get("port", 3306)),
            user=str(mysql_cfg.get("user")),
            password=mysql_password,
            database=str(mysql_cfg.get("database")),
            connect_timeout=5,
            read_timeout=30,
            write_timeout=30,
        )
        cursor_class = getattr(pymysql.cursors, "SSCursor", None) or pymysql.cursors.Cursor
        with conn.cursor(cursor_class) as cur:
            cur.execute(f"SELECT * FROM `{export_table}`;")
            cols = [d[0] for d in cur.description]

            _ensure_dir(out_csv.parent)
            with out_csv.open("w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(cols)
                rows = 0
                for row in cur:
                    w.writerow(list(row))
                    rows += 1

        conn.close()
        payload["artifacts"]["csv_export"] = {
            "table": export_table,
            "rows": rows,
            "path": str(out_csv),
            "sha256": _sha256_file(out_csv),
        }
    except Exception as e:
        code = _worst(code, CRITICAL)
        payload["artifacts"]["csv_export_error"] = str(e)

    _write_json(out_json, payload)

    summary = "BACKUP OK" if code == OK else "BACKUP CRITICAL"
    artifacts = [str(out_json)]
    if out_sql.exists():
        artifacts.append(str(out_sql))
    if out_csv.exists():
        artifacts.append(str(out_csv))

    return {
        "code": code,
        "summary": summary,
        "artifacts": artifacts,
        "data": payload,
    }


# =========================
# Module 3 — Audit d’obsolescence
# =========================
def _guess_os(open_ports: set[int]) -> str:
    if open_ports.intersection({135, 445, 3389}):
        return "windows"
    if 22 in open_ports:
        return "linux"
    if 80 in open_ports:
        return "unknown_web"
    return "unknown"


def run_audit_scan(cfg: dict[str, Any], cidr: str | None = None) -> dict[str, Any]:
    ts = _ts_utc_compact()
    cidr = cidr or str(cfg["audit"].get("default_scan_cidr", "192.168.10.0/24"))
    ports = [int(p) for p in cfg["audit"].get("scan_ports", [22, 80, 135, 445, 3389])]
    timeout = float(cfg["audit"].get("timeout_sec", 1.0))

    out_dir = Path(cfg["reports_dir"]) / "audit"
    out_json = out_dir / f"{ts}_scan_{cidr.replace('/','_')}.json"

    net = ipaddress.ip_network(cidr, strict=False)

    def probe(ip: str) -> dict[str, Any] | None:
        # Ping peut être bloqué -> on tente aussi TCP
        if not _ping(ip, timeout_sec=max(1, int(timeout))):
            if not any(_tcp_check(ip, p, timeout) for p in ports[:2]):
                return None

        open_ports: set[int] = set()
        for p in ports:
            if _tcp_check(ip, p, timeout):
                open_ports.add(p)

        if not open_ports:
            return None

        return {
            "ip": ip,
            "open_ports": sorted(open_ports),
            "os_guess": _guess_os(open_ports),
        }

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=128) as ex:
        futs = {ex.submit(probe, str(h)): str(h) for h in net.hosts()}
        for fut in as_completed(futs):
            r = fut.result()
            if r:
                results.append(r)

    payload = {
        "module": "audit_scan",
        "timestamp_utc": ts,
        "cidr": cidr,
        "scan_ports": ports,
        "results": sorted(results, key=lambda x: x["ip"]),
    }
    _write_json(out_json, payload)

    return {
        "code": OK,
        "summary": f"AUDIT SCAN OK ({len(results)} hôtes détectés)",
        "artifacts": [str(out_json)],
        "data": payload,
    }


def _http_get_json(url: str, timeout_sec: int = 10) -> Any:
    req = Request(url, headers={"User-Agent": "NTL-SysToolbox/0.1"})
    with urlopen(req, timeout=timeout_sec) as resp:
        raw = resp.read()
    return json.loads(raw.decode("utf-8"))


def run_audit_eol_versions(cfg: dict[str, Any], os_name: str) -> dict[str, Any]:
    ts = _ts_utc_compact()
    out_dir = Path(cfg["reports_dir"]) / "audit"
    out_json = out_dir / f"{ts}_eol_{os_name}.json"

    base = str(cfg["audit"].get("eol_api_base", "https://endoflife.date/api")).rstrip("/")
    url = f"{base}/{os_name}.json"

    code = OK
    payload: dict[str, Any] = {
        "module": "audit_eol_versions",
        "timestamp_utc": ts,
        "os_name": os_name,
        "source": url,
        "versions": None,
    }

    try:
        payload["versions"] = _http_get_json(url, timeout_sec=10)
    except HTTPError as e:
        code = CRITICAL
        payload["error"] = f"HTTP {e.code}"
    except URLError as e:
        code = CRITICAL
        payload["error"] = f"URL error: {e}"
    except Exception as e:
        code = CRITICAL
        payload["error"] = str(e)

    _write_json(out_json, payload)

    summary = "EOL LIST OK" if code == OK else "EOL LIST CRITICAL"
    return {
        "code": code,
        "summary": summary,
        "artifacts": [str(out_json)],
        "data": payload,
    }


def _find_eol(versions: list[dict[str, Any]], target_version: str) -> str | None:
    tv = target_version.strip()
    for item in versions:
        if str(item.get("cycle", "")).strip() == tv:
            eol = item.get("eol")
            return str(eol) if eol else None
    return None


def run_audit_report_from_csv(cfg: dict[str, Any], csv_path: str) -> dict[str, Any]:
    ts = _ts_utc_compact()
    out_dir = Path(cfg["reports_dir"]) / "audit"
    out_json = out_dir / f"{ts}_audit_report.json"
    out_html = out_dir / f"{ts}_audit_report.html"

    base = str(cfg["audit"].get("eol_api_base", "https://endoflife.date/api")).rstrip("/")
    soon_days = int(cfg["audit"].get("soon_days", 180))
    timeout = float(cfg["audit"].get("timeout_sec", 1.0))

    # lecture CSV attendu : host, os, version (noms flexibles mais on essaye standard)
    rows: list[dict[str, str]] = []
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            rows.append({k: (v or "").strip() for k, v in r.items()})

    def pick(d: dict[str, str], *keys: str) -> str:
        for k in keys:
            if k in d and d[k]:
                return d[k]
        return ""

    # cache EOL par OS
    eol_cache: dict[str, list[dict[str, Any]]] = {}

    def get_versions(os_name: str) -> list[dict[str, Any]]:
        if os_name in eol_cache:
            return eol_cache[os_name]
        url = f"{base}/{os_name}.json"
        v = _http_get_json(url, timeout_sec=10)
        if not isinstance(v, list):
            raise RuntimeError("Format EOL inattendu")
        eol_cache[os_name] = v
        return v

    today = date.today()
    code = OK
    findings: list[dict[str, Any]] = []

    for r in rows:
        host = pick(r, "host", "hostname", "ip")
        os_name = pick(r, "os", "os_name", "system").lower()
        version = pick(r, "version", "cycle", "os_version")

        item: dict[str, Any] = {
            "host": host,
            "os": os_name,
            "version": version,
            "eol": None,
            "status": "UNKNOWN",
        }

        try:
            versions = get_versions(os_name)
            eol_str = _find_eol(versions, version)
            item["eol"] = eol_str

            if not eol_str:
                item["status"] = "UNKNOWN"
                code = _worst(code, UNKNOWN)
            else:
                eol_date = datetime.strptime(eol_str, "%Y-%m-%d").date()
                delta = (eol_date - today).days
                if delta < 0:
                    item["status"] = "EOL"
                    code = _worst(code, CRITICAL)
                elif delta <= soon_days:
                    item["status"] = "SOON"
                    code = _worst(code, WARNING)
                else:
                    item["status"] = "SUPPORTED"
        except Exception as e:
            item["error"] = str(e)
            item["status"] = "UNKNOWN"
            code = _worst(code, UNKNOWN)

        findings.append(item)

    payload = {
        "module": "audit_report_from_csv",
        "timestamp_utc": ts,
        "input_csv": csv_path,
        "soon_days": soon_days,
        "results": findings,
    }
    _write_json(out_json, payload)

    # rapport HTML exploitable
    def badge(status: str) -> str:
        if status == "SUPPORTED":
            return "OK"
        if status == "SOON":
            return "WARNING"
        if status == "EOL":
            return "CRITICAL"
        return "UNKNOWN"

    html_rows = []
    for it in findings:
        html_rows.append(
            "<tr>"
            f"<td>{html_escape(it.get('host',''))}</td>"
            f"<td>{html_escape(it.get('os',''))}</td>"
            f"<td>{html_escape(it.get('version',''))}</td>"
            f"<td>{html_escape(str(it.get('eol','')))}</td>"
            f"<td>{html_escape(badge(it.get('status','UNKNOWN')))}</td>"
            "</tr>"
        )

    html = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>NTL - Audit Obsolescence</title>"
        "<style>"
        "body{font-family:Arial,sans-serif;margin:20px}"
        "table{border-collapse:collapse;width:100%}"
        "th,td{border:1px solid #ddd;padding:8px}"
        "th{background:#f3f3f3;text-align:left}"
        "</style>"
        "</head><body>"
        f"<h1>Audit d’obsolescence</h1>"
        f"<p>Généré: {html_escape(ts)} UTC</p>"
        f"<p>Seuil 'bientôt EOL': {soon_days} jours</p>"
        "<table><thead><tr>"
        "<th>Host</th><th>OS</th><th>Version</th><th>EOL</th><th>Statut</th>"
        "</tr></thead><tbody>"
        + "".join(html_rows)
        + "</tbody></table></body></html>"
    )
    _write_text(out_html, html)

    summary = "AUDIT REPORT OK"
    if code == WARNING:
        summary = "AUDIT REPORT WARNING"
    elif code == CRITICAL:
        summary = "AUDIT REPORT CRITICAL"
    elif code == UNKNOWN:
        summary = "AUDIT REPORT UNKNOWN"

    return {
        "code": code,
        "summary": summary,
        "artifacts": [str(out_json), str(out_html)],
        "data": payload,
    }
