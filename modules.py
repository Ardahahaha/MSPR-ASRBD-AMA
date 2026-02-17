# src/ntlsystoolbox/modules.py
from __future__ import annotations

import csv
import hashlib
import ipaddress
import json
import os
import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ============================================================
# Result model (ex-core/result.py + exit codes)
# ============================================================
_STATUS_TO_EXIT = {
    "SUCCESS": 0,
    "WARNING": 1,
    "CRITICAL": 2,
    "ERROR": 3,
    "UNKNOWN": 4,
}


def status_from_two_flags(a_ok: bool, b_ok: bool) -> str:
    if a_ok and b_ok:
        return "SUCCESS"
    if (a_ok and not b_ok) or (b_ok and not a_ok):
        return "WARNING"
    return "ERROR"


@dataclass
class ModuleResult:
    module: str = "module"
    status: str = "UNKNOWN"
    summary: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, str] = field(default_factory=dict)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    exit_code: Optional[int] = None

    def finish(self) -> "ModuleResult":
        if not self.finished_at:
            self.finished_at = datetime.now().isoformat(timespec="seconds")
        st = (self.status or "UNKNOWN").upper()
        self.status = st
        if self.exit_code is None:
            self.exit_code = _STATUS_TO_EXIT.get(st, 4)
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "status": self.status,
            "exit_code": self.exit_code,
            "summary": self.summary,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "details": self.details or {},
            "artifacts": self.artifacts or {},
        }


# ============================================================
# Reports helpers (ex-main.py)
# ============================================================
def _ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def save_json_report(result: ModuleResult, out_dir: str = "reports/json") -> str:
    _ensure_dir(out_dir)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_module = (result.module or "module").replace(" ", "_").replace("-", "_").lower()
    path = str(Path(out_dir) / f"{safe_module}_{ts}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
    return path


def print_result(
    result: ModuleResult,
    json_path: Optional[str] = None,
    *,
    json_only: bool = False,
    quiet: bool = False,
    verbose: bool = False,
) -> None:
    def _p(s: str = "") -> None:
        print(s)

    def _kv(k: str, v: Any, indent: int = 0) -> None:
        pad = " " * indent
        _p(f"{pad}- {k}: {v}")

    def _print_diagnostic(details: Dict[str, Any]) -> None:
        targets = details.get("targets", {}) or {}
        ad = details.get("ad_dns", {}) or {}
        mysql = details.get("mysql", {}) or {}
        local = details.get("local", {}) or {}

        _p("\nDétails clés (Diagnostic) :")
        _kv("DC01", targets.get("dc01"))
        _kv("DC02", targets.get("dc02"))
        _kv("WMS-DB", targets.get("wms_db"))
        _kv("WMS-APP", targets.get("wms_app"))

        _p("\nAD/DNS :")
        _kv("overall_ok", ad.get("overall_ok"))
        for dc in ("dc01", "dc02"):
            dc_obj = ad.get(dc, {}) or {}
            _kv(f"{dc}.overall_ok", dc_obj.get("overall_ok"), indent=2)
            _kv(f"{dc}.dns_tcp_53.ok", (dc_obj.get("dns_tcp_53", {}) or {}).get("ok"), indent=2)
            _kv(f"{dc}.kerberos_88.ok", (dc_obj.get("kerberos_88", {}) or {}).get("ok"), indent=2)
            _kv(f"{dc}.ldap_389.ok", (dc_obj.get("ldap_389", {}) or {}).get("ok"), indent=2)

        _p("\nMySQL :")
        _kv("ok", mysql.get("ok"))
        _kv("version", mysql.get("version"))
        if not mysql.get("ok"):
            _kv("error", mysql.get("msg"))

        _p("\nSystème local :")
        _kv("hostname", local.get("hostname"))
        _kv("cpu_percent", local.get("cpu_percent"))
        _kv("ram_percent", local.get("ram_percent"))
        _kv("disk_system_percent", local.get("disk_system_percent"))

    def _print_backup(details: Dict[str, Any], artifacts: Dict[str, str]) -> None:
        _p("\nDétails clés (Backup WMS) :")
        _kv("host", details.get("host"))
        _kv("port", details.get("port"))
        _kv("db", details.get("db"))
        _kv("sql", details.get("sql"))
        _kv("csv", details.get("csv"))
        _kv("csv_table", details.get("csv_table"))
        if artifacts:
            _p("\nArtifacts :")
            for k, v in artifacts.items():
                _kv(k, v)

    def _print_obsolescence(details: Dict[str, Any], artifacts: Dict[str, str]) -> None:
        action = details.get("action")
        _p("\nDétails clés (Audit obsolescence) :")
        _kv("action", action)

        if action == "scan_range":
            stats = details.get("stats", {}) or {}
            inv = details.get("inventory", []) or []
            _kv("cidr", stats.get("cidr"))
            _kv("found_hosts", stats.get("found_hosts"))
            _kv("ports_checked", stats.get("ports_checked"))
            if inv:
                _p("\nAperçu inventaire (max 10) :")
                for h in inv[:10]:
                    _kv("ip", h.get("ip"), indent=2)
                    _kv("open_ports", h.get("open_ports"), indent=4)
                    _kv("os_guess", h.get("os_guess"), indent=4)

        elif action == "list_versions_eol":
            product = details.get("product")
            rows = details.get("rows", []) or []
            _kv("product", product)
            _kv("rows_count", len(rows))
            if rows:
                _p("\nAperçu versions (max 12) :")
                for r in rows[:12]:
                    _kv("cycle", r.get("cycle"), indent=2)
                    _kv("latest", r.get("latest"), indent=4)
                    _kv("eol", r.get("eol_date") or r.get("eol"), indent=4)
                    _kv("status", r.get("support_status"), indent=4)

        elif action in ("csv_to_report", "csv_to_eol_and_report"):
            report = details.get("report", {}) or {}
            scan = details.get("scan", {}) or {}
            counts = (report.get("counts") or {})
            _kv("csv_path", details.get("csv_path"))
            _kv("scan_enabled", scan.get("enabled"))
            _kv("inventory_count", scan.get("inventory_count"))
            _kv("OK", counts.get("OK"))
            _kv("SOON", counts.get("SOON"))
            _kv("EOL", counts.get("EOL"))
            _kv("UNKNOWN", counts.get("UNKNOWN"))

        if artifacts:
            _p("\nArtifacts :")
            for k, v in artifacts.items():
                _kv(k, v)

    if json_only:
        print(json_path or "")
        return

    if quiet:
        print(
            f"{result.module} {result.status} - {result.summary}"
            + (f" | {json_path}" if json_path else "")
        )
        return

    print("\n==============================")
    print(f"MODULE : {result.module}")
    print(f"STATUT : {result.status} (exit_code={result.exit_code})")
    print(f"RÉSUMÉ : {result.summary}")
    if json_path:
        print(f"JSON : {json_path}")
    print("==============================")

    if verbose:
        try:
            if result.module == "diagnostic":
                _print_diagnostic(result.details or {})
            elif result.module in ("backup_wms", "backup-wms"):
                _print_backup(result.details or {}, result.artifacts or {})
            elif result.module in ("obsolescence", "audit_obsolescence", "audit-obsolescence"):
                _print_obsolescence(result.details or {}, result.artifacts or {})
            else:
                print("\nDétails :")
                print(json.dumps(result.details or {}, indent=2, ensure_ascii=False))
        except Exception:
            print("\nDétails :")
            print(json.dumps(result.details or {}, indent=2, ensure_ascii=False))


# ============================================================
# Small utils
# ============================================================
def _env(key: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(key)
    return v if v not in (None, "") else default


def _prompt(msg: str, default: Optional[str] = None, *, secret: bool = False) -> str:
    # mode non-interactif
    if os.getenv("NTL_NON_INTERACTIVE", "0") == "1":
        return default or ""
    suffix = f" [{default}]" if default else ""
    if secret:
        # getpass si dispo
        try:
            from getpass import getpass

            v = getpass(f"{msg}{suffix} : ").strip()
            return v if v else (default or "")
        except Exception:
            pass
    v = input(f"{msg}{suffix} : ").strip()
    return v if v else (default or "")


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _tcp_check(host: str, port: int, timeout_s: float = 2.0) -> Tuple[bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True, "OK"
    except Exception as e:
        return False, str(e)


def _ping(host: str, timeout_s: int = 2) -> bool:
    try:
        if platform.system().lower().startswith("win"):
            cmd = ["ping", "-n", "1", "-w", str(timeout_s * 1000), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout_s), host]
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except Exception:
        return False


# ============================================================
# DiagnosticModule (AD/DNS/MySQL + snapshot)
# ============================================================
@dataclass
class InfraTargets:
    dc01: str
    dc02: str
    wms_db: str
    wms_app: str


def _read_linux_pretty_os() -> Optional[str]:
    try:
        path = "/etc/os-release"
        if not os.path.exists(path):
            return None
        data: Dict[str, str] = {}
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                data[k] = v.strip().strip('"')
        return data.get("PRETTY_NAME") or data.get("NAME")
    except Exception:
        return None


def _local_system_snapshot() -> Dict[str, Any]:
    # psutil obligatoire (mêmes features que ton module actuel)
    try:
        import psutil  # type: ignore
    except Exception as e:
        return {
            "error": "psutil manquant",
            "hint": "pip install psutil",
            "exception": str(e),
        }

    hostname = socket.gethostname()
    os_name = platform.system()
    os_release = platform.release()
    os_version = platform.version()
    pretty = _read_linux_pretty_os()

    boot_ts = psutil.boot_time()
    uptime_s = int(datetime.now().timestamp() - boot_ts)
    cpu_percent = psutil.cpu_percent(interval=0.5)
    vm = psutil.virtual_memory()

    disks: List[Dict[str, Any]] = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            disks.append(
                {
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total_gb": round(usage.total / (1024**3), 2),
                    "used_gb": round(usage.used / (1024**3), 2),
                    "free_gb": round(usage.free / (1024**3), 2),
                    "percent": float(usage.percent),
                }
            )
        except Exception:
            continue

    if os_name.lower().startswith("win"):
        root = os.environ.get("SystemDrive", "C:") + "\\"
    else:
        root = "/"
    try:
        root_usage = psutil.disk_usage(root)
        disk_percent = float(root_usage.percent)
    except Exception:
        disk_percent = None

    return {
        "hostname": hostname,
        "os": {"system": os_name, "release": os_release, "version": os_version, "pretty_name": pretty},
        "uptime_seconds": uptime_s,
        "cpu_percent": float(cpu_percent),
        "ram_percent": float(vm.percent),
        "ram_total_gb": round(vm.total / (1024**3), 2),
        "disk_system_percent": disk_percent,
        "disks": disks,
    }


class DiagnosticModule:
    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}

    def _load_targets(self) -> InfraTargets:
        infra = self.config.get("infrastructure", {}) if isinstance(self.config, dict) else {}
        dc01_default = _env("NTL_DC01_IP", infra.get("dc01_ip", "192.168.10.10"))
        dc02_default = _env("NTL_DC02_IP", infra.get("dc02_ip", "192.168.10.11"))
        wmsdb_default = _env("NTL_WMSDB_IP", infra.get("wms_db_ip", "192.168.10.21"))
        wmsapp_default = _env("NTL_WMSAPP_IP", infra.get("wms_app_ip", "192.168.10.22"))

        print("\n--- Diagnostic Système ---\n")
        dc01 = _prompt("IP DC01 (AD/DNS)", dc01_default)
        dc02 = _prompt("IP DC02 (AD/DNS)", dc02_default)
        wms_db = _prompt("IP WMS-DB (MySQL)", wmsdb_default)
        wms_app = _prompt("IP WMS-APP (optionnel)", wmsapp_default)

        return InfraTargets(dc01=dc01, dc02=dc02, wms_db=wms_db, wms_app=wms_app)

    def _mysql_check(self, host: str) -> Tuple[bool, str, Optional[str]]:
        try:
            import pymysql  # type: ignore
        except Exception as e:
            return False, f"pymysql manquant: {e}", None

        db_cfg = self.config.get("database", {}) if isinstance(self.config, dict) else {}
        port = int(_env("NTL_DB_PORT", str(db_cfg.get("port", 3306))) or "3306")
        user = _env("NTL_DB_USER", db_cfg.get("user", "root")) or "root"
        password = _env("NTL_DB_PASS", db_cfg.get("password", "")) or ""
        dbname = _env("NTL_DB_NAME", db_cfg.get("name", "")) or ""

        user = _prompt("MySQL user", user)
        password = _prompt("MySQL password (vide si aucun)", password, secret=True)
        dbname = _prompt("MySQL database (optionnel)", dbname)

        try:
            conn = pymysql.connect(
                host=host,
                port=port,
                user=user,
                password=password,
                database=dbname if dbname else None,
                connect_timeout=3,
                read_timeout=3,
                write_timeout=3,
                charset="utf8mb4",
                autocommit=True,
            )
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
                cur.execute("SELECT VERSION()")
                v = cur.fetchone()
                version = v[0] if v else None
            conn.close()
            return True, "OK", version
        except Exception as e:
            return False, str(e), None

    def run(self) -> ModuleResult:
        started = datetime.now().isoformat(timespec="seconds")
        targets = self._load_targets()
        local = _local_system_snapshot()

        # Si psutil manquant, on continue quand même (mais warning)
        psutil_missing = bool(isinstance(local, dict) and local.get("error") == "psutil manquant")

        ping_dc01 = _ping(targets.dc01)
        ping_dc02 = _ping(targets.dc02)
        ping_wmsdb = _ping(targets.wms_db)
        ping_wmsapp = _ping(targets.wms_app) if targets.wms_app else False

        dc01_dns_ok, dc01_dns_msg = _tcp_check(targets.dc01, 53)
        dc02_dns_ok, dc02_dns_msg = _tcp_check(targets.dc02, 53)
        dc01_krb_ok, dc01_krb_msg = _tcp_check(targets.dc01, 88)
        dc02_krb_ok, dc02_krb_msg = _tcp_check(targets.dc02, 88)
        dc01_ldap_ok, dc01_ldap_msg = _tcp_check(targets.dc01, 389)
        dc02_ldap_ok, dc02_ldap_msg = _tcp_check(targets.dc02, 389)

        dc01_ad_dns_ok = dc01_dns_ok and dc01_krb_ok and dc01_ldap_ok
        dc02_ad_dns_ok = dc02_dns_ok and dc02_krb_ok and dc02_ldap_ok
        ad_dns_ok = dc01_ad_dns_ok or dc02_ad_dns_ok

        print("\nTest MySQL (WMS-DB)...")
        mysql_ok, mysql_msg, mysql_version = self._mysql_check(targets.wms_db)

        thresholds = self.config.get("thresholds", {}) if isinstance(self.config, dict) else {}
        cpu_warn_th = float(_env("NTL_CPU_WARN", str(thresholds.get("cpu_warn", 90))) or "90")
        ram_warn_th = float(_env("NTL_RAM_WARN", str(thresholds.get("ram_warn", 90))) or "90")
        disk_warn_th = float(_env("NTL_DISK_WARN", str(thresholds.get("disk_warn", 90))) or "90")

        cpu_warn = False
        ram_warn = False
        disk_warn = False
        if not psutil_missing:
            cpu_warn = float(local.get("cpu_percent", 0.0)) >= cpu_warn_th
            ram_warn = float(local.get("ram_percent", 0.0)) >= ram_warn_th
            dsp = local.get("disk_system_percent")
            disk_warn = (dsp is not None) and (float(dsp) >= disk_warn_th)

        # Statut : on reste sur ta logique (ERROR si AD/DNS ou MySQL KO)
        if not ad_dns_ok or not mysql_ok:
            status = "ERROR"
        else:
            status = "SUCCESS"
            if dc01_ad_dns_ok != dc02_ad_dns_ok:
                status = "WARNING"
            if cpu_warn or ram_warn or disk_warn or psutil_missing:
                status = "WARNING"

        summary = "AD/DNS OK, MySQL OK" if (ad_dns_ok and mysql_ok) else "Problème AD/DNS ou MySQL"
        if psutil_missing:
            summary += " (snapshot limité: psutil manquant)"

        details: Dict[str, Any] = {
            "targets": {
                "dc01": targets.dc01,
                "dc02": targets.dc02,
                "wms_db": targets.wms_db,
                "wms_app": targets.wms_app,
            },
            "ping": {"dc01": ping_dc01, "dc02": ping_dc02, "wms_db": ping_wmsdb, "wms_app": ping_wmsapp},
            "ad_dns": {
                "dc01": {
                    "dns_tcp_53": {"ok": dc01_dns_ok, "msg": dc01_dns_msg},
                    "kerberos_88": {"ok": dc01_krb_ok, "msg": dc01_krb_msg},
                    "ldap_389": {"ok": dc01_ldap_ok, "msg": dc01_ldap_msg},
                    "overall_ok": dc01_ad_dns_ok,
                },
                "dc02": {
                    "dns_tcp_53": {"ok": dc02_dns_ok, "msg": dc02_dns_msg},
                    "kerberos_88": {"ok": dc02_krb_ok, "msg": dc02_krb_msg},
                    "ldap_389": {"ok": dc02_ldap_ok, "msg": dc02_ldap_msg},
                    "overall_ok": dc02_ad_dns_ok,
                },
                "overall_ok": ad_dns_ok,
            },
            "mysql": {"ok": mysql_ok, "msg": mysql_msg, "version": mysql_version},
            "local": local,
            "thresholds": {"cpu_warn": cpu_warn_th, "ram_warn": ram_warn_th, "disk_warn": disk_warn_th},
        }

        return ModuleResult(
            module="diagnostic",
            status=status,
            summary=summary,
            details=details,
            artifacts={},
            started_at=started,
        ).finish()


# ============================================================
# BackupWMSModule (SQL dump + CSV export + sha256)
# ============================================================
@dataclass
class DBConfig:
    host: str
    port: int
    user: str
    password: str
    db: str
    csv_table: Optional[str] = None


class BackupWMSModule:
    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}

    def _load_db_config(self) -> DBConfig:
        db_cfg = self.config.get("database", {}) if isinstance(self.config, dict) else {}
        default_host = _env("NTL_DB_HOST", db_cfg.get("host", "192.168.10.21"))
        default_port = _env("NTL_DB_PORT", str(db_cfg.get("port", 3306)))
        default_user = _env("NTL_DB_USER", db_cfg.get("user", "root"))
        default_db = _env("NTL_DB_NAME", db_cfg.get("name", "wms"))
        default_table = _env("NTL_DB_TABLE", db_cfg.get("table", "")) or None

        print("\n--- Configuration Sauvegarde WMS ---\n")
        host = _prompt("Host MySQL (ex: 192.168.10.21)", default_host)
        port_str = _prompt("Port MySQL", default_port)
        try:
            port = int(port_str)
        except ValueError:
            port = 3306
        user = _prompt("Utilisateur", default_user)

        pwd = _env("NTL_DB_PASS", db_cfg.get("password", ""))
        if not pwd:
            pwd = _prompt("Mot de passe (vide si aucun)", "", secret=True)

        db = _prompt("Nom de la base", default_db)
        table = _prompt("Table à exporter en CSV (optionnel)", default_table or "")
        csv_table = table.strip() or None

        return DBConfig(host=host, port=port, user=user, password=pwd or "", db=db, csv_table=csv_table)

    def _connect(self, dbc: DBConfig):
        import pymysql  # type: ignore

        return pymysql.connect(
            host=dbc.host,
            port=dbc.port,
            user=dbc.user,
            password=dbc.password,
            database=dbc.db,
            charset="utf8mb4",
            cursorclass=pymysql.cursors.Cursor,
            autocommit=True,
        )

    def _fetch_tables(self, conn) -> List[str]:
        with conn.cursor() as cur:
            cur.execute("SHOW TABLES")
            rows = cur.fetchall()
        return [r[0] for r in rows]

    def _dump_sql(self, conn, dbc: DBConfig, out_dir: str) -> Tuple[bool, str, Optional[str]]:
        try:
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            out_path = str(Path(out_dir) / f"wms_backup_{dbc.db}_{ts}.sql")

            tables = self._fetch_tables(conn)
            if not tables:
                return False, "Aucune table trouvée dans la base.", None

            with open(out_path, "w", encoding="utf-8") as f:
                f.write("-- NTL SysToolbox SQL Backup\n")
                f.write(f"-- Database: {dbc.db}\n")
                f.write(f"-- Generated: {datetime.now().isoformat(timespec='seconds')}\n\n")
                f.write("SET FOREIGN_KEY_CHECKS=0;\n\n")

                for table in tables:
                    with conn.cursor() as cur:
                        cur.execute(f"SHOW CREATE TABLE `{table}`")
                        row = cur.fetchone()
                        create_stmt = row[1] if row and len(row) > 1 else None
                    if not create_stmt:
                        continue

                    f.write(f"-- Table: `{table}`\n")
                    f.write(f"DROP TABLE IF EXISTS `{table}`;\n")
                    f.write(create_stmt + ";\n\n")

                    with conn.cursor() as cur:
                        cur.execute(f"SELECT * FROM `{table}`")
                        cols = [d[0] for d in cur.description] if cur.description else []
                        if not cols:
                            f.write("\n")
                            continue
                        col_list = ", ".join(f"`{c}`" for c in cols)

                        while True:
                            rows = cur.fetchmany(500)
                            if not rows:
                                break
                            f.write(f"INSERT INTO `{table}` ({col_list}) VALUES\n")
                            values_lines = []
                            for r in rows:
                                vals = []
                                for v in r:
                                    if isinstance(v, (bytes, bytearray)):
                                        vals.append("0x" + bytes(v).hex())
                                    else:
                                        vals.append(conn.escape(v))
                                values_lines.append("(" + ", ".join(vals) + ")")
                            f.write(",\n".join(values_lines) + ";\n\n")

                f.write("SET FOREIGN_KEY_CHECKS=1;\n")

            return True, "Dump SQL généré.", out_path
        except Exception as e:
            return False, f"{e}", None

    def _export_csv(self, conn, dbc: DBConfig, out_dir: str) -> Tuple[bool, str, Optional[str]]:
        try:
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")

            tables = self._fetch_tables(conn)
            if not tables:
                return False, "Aucune table trouvée dans la base.", None

            table = dbc.csv_table or tables[0]
            if table not in tables:
                return False, f"Table '{table}' introuvable. Tables dispo: {', '.join(tables[:10])}", None

            out_path = str(Path(out_dir) / f"wms_export_{table}_{ts}.csv")
            with conn.cursor() as cur:
                cur.execute(f"SELECT * FROM `{table}`")
                cols = [d[0] for d in cur.description] if cur.description else []

                with open(out_path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    if cols:
                        w.writerow(cols)
                    while True:
                        rows = cur.fetchmany(1000)
                        if not rows:
                            break
                        w.writerows(rows)

            return True, f"Export CSV généré (table={table}).", out_path
        except Exception as e:
            return False, f"{e}", None

    def run(self) -> ModuleResult:
        started = datetime.now().isoformat(timespec="seconds")
        dbc = self._load_db_config()

        print("\nExécution des sauvegardes...")
        try:
            conn = self._connect(dbc)
        except Exception as e:
            msg = f"Connexion MySQL impossible: {e}"
            return ModuleResult(
                module="backup_wms",
                status="ERROR",
                summary="Sauvegarde WMS impossible (connexion DB KO)",
                details={
                    "host": dbc.host,
                    "port": dbc.port,
                    "db": dbc.db,
                    "sql": f"FAIL ({msg})",
                    "csv": f"FAIL ({msg})",
                },
                artifacts={},
                started_at=started,
            ).finish()

        sql_ok = False
        csv_ok = False
        sql_msg = ""
        csv_msg = ""
        sql_path: Optional[str] = None
        csv_path: Optional[str] = None

        try:
            sql_ok, sql_msg, sql_path = self._dump_sql(conn, dbc, out_dir="reports/backup/sql")
            print(f"SQL: {'OK' if sql_ok else 'ERROR'} ({sql_msg})")
            csv_ok, csv_msg, csv_path = self._export_csv(conn, dbc, out_dir="reports/backup/csv")
            print(f"CSV: {'OK' if csv_ok else 'ERROR'} ({csv_msg})")
        finally:
            try:
                conn.close()
            except Exception:
                pass

        status = status_from_two_flags(sql_ok, csv_ok)
        artifacts: Dict[str, str] = {}
        if sql_ok and sql_path:
            artifacts["sql_backup_path"] = sql_path
            artifacts["sql_backup_sha256"] = _sha256_file(sql_path)
        if csv_ok and csv_path:
            artifacts["csv_export_path"] = csv_path
            artifacts["csv_export_sha256"] = _sha256_file(csv_path)

        return ModuleResult(
            module="backup_wms",
            status=status,
            summary="Sauvegarde WMS SQL/CSV",
            details={
                "host": dbc.host,
                "port": dbc.port,
                "db": dbc.db,
                "sql": "OK" if sql_ok else f"FAIL ({sql_msg})",
                "csv": "OK" if csv_ok else f"FAIL ({csv_msg})",
                "csv_table": dbc.csv_table or "(auto)",
            },
            artifacts=artifacts,
            started_at=started,
        ).finish()


# ============================================================
# AuditObsolescenceModule (scan range / EOL lookup / CSV->HTML)
# ============================================================
@dataclass
class EOLMeta:
    source: str
    fetched_at_iso: str
    api_mode: str  # v1 / v0 / cache


class EOLProvider:
    """
    endoflife.date:
    - v1: https://endoflife.date/api/v1/products/{product}/
    - v0: https://endoflife.date/api/{product}.json
    Cache local: reports/audit/eol_cache.json
    """

    def __init__(self, cache_path: str = "reports/audit/eol_cache.json", ttl_hours: int = 24):
        self.cache_path = cache_path
        self.ttl_hours = ttl_hours
        self._cache: Dict[str, Any] = self._load_cache()

    def _load_cache(self) -> Dict[str, Any]:
        try:
            if os.path.exists(self.cache_path):
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return {}

    def _save_cache(self) -> None:
        try:
            _ensure_dir(str(Path(self.cache_path).parent))
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def _cache_valid(self, fetched_at_iso: str) -> bool:
        try:
            fetched = datetime.fromisoformat(fetched_at_iso)
            return (datetime.now() - fetched).total_seconds() <= self.ttl_hours * 3600
        except Exception:
            return False

    def fetch_product(self, product: str) -> Tuple[List[Dict[str, Any]], EOLMeta]:
        try:
            import requests  # type: ignore
        except Exception as e:
            return [], EOLMeta(source="(requests manquant)", fetched_at_iso="", api_mode=str(e))

        product = product.strip().lower()
        cached = self._cache.get(product)
        if cached and isinstance(cached, dict) and self._cache_valid(cached.get("fetched_at_iso", "")):
            return cached.get("data", []), EOLMeta(
                source=cached.get("source", "endoflife.date"),
                fetched_at_iso=cached.get("fetched_at_iso", ""),
                api_mode=cached.get("api_mode", "cache"),
            )

        fetched_at_iso = datetime.now().isoformat(timespec="seconds")

        v1_url = f"https://endoflife.date/api/v1/products/{product}/"
        try:
            r = requests.get(v1_url, timeout=8)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list):
                    meta = EOLMeta(source="endoflife.date", fetched_at_iso=fetched_at_iso, api_mode="v1")
                    self._cache[product] = {
                        "data": data,
                        "fetched_at_iso": fetched_at_iso,
                        "source": meta.source,
                        "api_mode": meta.api_mode,
                    }
                    self._save_cache()
                    return data, meta
        except Exception:
            pass

        v0_url = f"https://endoflife.date/api/{product}.json"
        r = requests.get(v0_url, timeout=8)
        r.raise_for_status()
        data = r.json()
        if not isinstance(data, list):
            data = []
        meta = EOLMeta(source="endoflife.date", fetched_at_iso=fetched_at_iso, api_mode="v0")
        self._cache[product] = {"data": data, "fetched_at_iso": fetched_at_iso, "source": meta.source, "api_mode": meta.api_mode}
        self._save_cache()
        return data, meta


def _parse_date(d: Any) -> Optional[date]:
    if d is None:
        return None
    if isinstance(d, bool):
        return None
    if isinstance(d, str):
        try:
            return datetime.strptime(d, "%Y-%m-%d").date()
        except Exception:
            return None
    return None


def _status_from_eol(today: date, eol: Any, soon_days: int) -> Tuple[str, Optional[str]]:
    if eol is None:
        return "UNKNOWN", None
    if isinstance(eol, bool):
        return ("EOL" if eol else "OK"), None
    if isinstance(eol, str):
        d = _parse_date(eol)
        if not d:
            return "UNKNOWN", eol
        if d < today:
            return "EOL", d.isoformat()
        if (d - today).days <= soon_days:
            return "SOON", d.isoformat()
        return "OK", d.isoformat()
    return "UNKNOWN", None


def _tcp_ports(host: str, ports: List[int], timeout_s: float = 0.5) -> List[int]:
    open_ports: List[int] = []
    for p in ports:
        try:
            with socket.create_connection((host, p), timeout=timeout_s):
                open_ports.append(p)
        except Exception:
            pass
    return open_ports


def _guess_os_from_ports(open_ports: List[int]) -> str:
    if any(p in open_ports for p in (3389, 445, 139)):
        return "windows"
    if any(p in open_ports for p in (53, 389)):
        return "windows-server (dc/dns probable)"
    if 22 in open_ports:
        return "linux"
    return "unknown"


class AuditObsolescenceModule:
    def __init__(self, config: Dict[str, Any]):
        self.config = config or {}
        self.provider = EOLProvider()

    def _menu(self) -> str:
        print("\n--- Audit Obsolescence ---")
        print(" [1] Scanner une plage réseau (inventaire + OS probable)")
        print(" [2] Lister versions + EOL d’un produit/OS (ex: ubuntu, debian, windows, mysql, python)")
        print(" [3] Import CSV (composants + versions) + Générer rapport HTML")
        print(" [0] Retour\n")
        return input("Choix > ").strip()

    def _scan_range(self, cidr: str) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        ports = [22, 53, 80, 443, 389, 445, 3389, 3306]
        timeout_s = float(_env("NTL_SCAN_TIMEOUT", "0.4") or "0.4")
        workers = int(_env("NTL_SCAN_WORKERS", "120") or "120")

        net = ipaddress.ip_network(cidr, strict=False)
        ips = [str(ip) for ip in net.hosts()]

        results: List[Dict[str, Any]] = []

        def worker(ip: str) -> Optional[Dict[str, Any]]:
            open_p = _tcp_ports(ip, ports, timeout_s=timeout_s)
            if not open_p:
                return None
            return {"ip": ip, "open_ports": sorted(open_p), "os_guess": _guess_os_from_ports(open_p)}

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(worker, ip) for ip in ips]
            for f in as_completed(futs):
                item = f.result()
                if item:
                    results.append(item)

        results.sort(key=lambda x: tuple(int(p) for p in x["ip"].split(".")))
        stats = {
            "cidr": cidr,
            "found_hosts": len(results),
            "ports_checked": ports,
            "timeout_s": timeout_s,
            "workers": workers,
        }
        return results, stats

    def _list_versions_eol(self, product: str) -> Tuple[List[Dict[str, Any]], EOLMeta]:
        data, meta = self.provider.fetch_product(product)
        rows: List[Dict[str, Any]] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "cycle": item.get("cycle") or item.get("release") or item.get("version"),
                    "latest": item.get("latest"),
                    "eol": item.get("eol"),
                    "support": item.get("support"),
                    "extendedSupport": item.get("extendedSupport"),
                    "link": item.get("link"),
                    "releaseDate": item.get("releaseDate") or item.get("released"),
                }
            )
        rows = [r for r in rows if r.get("cycle")]
        return rows, meta

    def _read_components_csv(self, path: str) -> List[Dict[str, str]]:
        if not os.path.exists(path):
            raise FileNotFoundError(f"CSV introuvable: {path}")

        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            sample = f.read(2048)
            f.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=";,")
            except Exception:
                dialect = csv.excel
            reader = csv.DictReader(f, dialect=dialect)

            items: List[Dict[str, str]] = []
            for row in reader:
                product = (
                    (row.get("product") or row.get("os") or row.get("OS") or row.get("Produit") or row.get("produit") or "")
                    .strip()
                    .lower()
                )
                version = (row.get("version") or row.get("cycle") or row.get("Version") or row.get("version_os") or "").strip()
                name = (
                    (row.get("name") or row.get("hostname") or row.get("machine") or row.get("composant") or row.get("Composant") or "")
                    .strip()
                )
                if not product or not version:
                    continue
                items.append({"name": name or "(n/a)", "product": product, "version": version})
            return items

    def _match_cycle(self, rows: List[Dict[str, Any]], version: str) -> Optional[Dict[str, Any]]:
        v = version.strip()
        for r in rows:
            c = str(r.get("cycle", "")).strip()
            if not c:
                continue
            if v == c or v.startswith(c + ".") or v.startswith(c + " "):
                return r
        return None

    def _generate_html_report(
        self,
        inventory: Optional[List[Dict[str, Any]]],
        components: List[Dict[str, Any]],
        out_path: str,
        meta_by_product: Dict[str, EOLMeta],
        soon_days: int,
    ) -> Dict[str, Any]:
        counts = {"OK": 0, "SOON": 0, "EOL": 0, "UNKNOWN": 0}
        for c in components:
            counts[c["support_status"]] += 1

        Path(out_path).parent.mkdir(parents=True, exist_ok=True)

        def esc(s: Any) -> str:
            return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        html = []
        html.append("<!doctype html><html><head><meta charset='utf-8'/>")
        html.append("<title>NTL SysToolbox - Audit d'obsolescence</title>")
        html.append(
            "<style>"
            "body{font-family:system-ui,Segoe UI,Roboto,Arial;margin:24px}"
            ".ok{color:#0a0}.soon{color:#b8860b}.eol{color:#c00}.unk{color:#777}"
            "table{border-collapse:collapse;width:100%;margin:12px 0}"
            "th,td{border:1px solid #ddd;padding:8px;font-size:14px}"
            "th{background:#f6f6f6;text-align:left}"
            "</style></head><body>"
        )
        html.append("<h1>Audit d'obsolescence</h1>")
        html.append(f"<p>Généré le {esc(datetime.now().isoformat(timespec='seconds'))} | Seuil SOON = {soon_days} jours</p>")

        html.append("<h2>Sources EOL</h2><ul>")
        for prod, m in meta_by_product.items():
            html.append(f"<li><b>{esc(prod)}</b> — source: {esc(m.source)} — fetch: {esc(m.fetched_at_iso)} — mode: {esc(m.api_mode)}</li>")
        html.append("</ul>")

        html.append("<h2>Résumé</h2><ul>")
        html.append(f"<li>OK: {counts['OK']}</li>")
        html.append(f"<li>SOON: {counts['SOON']}</li>")
        html.append(f"<li>EOL: {counts['EOL']}</li>")
        html.append(f"<li>UNKNOWN: {counts['UNKNOWN']}</li>")
        html.append("</ul>")

        if inventory is not None:
            html.append("<h2>Inventaire réseau (scan)</h2>")
            html.append("<table><thead><tr><th>IP</th><th>Ports ouverts</th><th>OS probable</th></tr></thead><tbody>")
            for h in inventory:
                html.append(
                    "<tr>"
                    f"<td>{esc(h.get('ip'))}</td>"
                    f"<td>{esc(','.join(str(p) for p in h.get('open_ports', [])))}</td>"
                    f"<td>{esc(h.get('os_guess'))}</td>"
                    "</tr>"
                )
            html.append("</tbody></table>")

        html.append("<h2>Composants (CSV) + statut support</h2>")
        html.append("<table><thead><tr><th>Composant</th><th>Produit</th><th>Version</th><th>EOL</th><th>Statut</th></tr></thead><tbody>")
        for c in components:
            st = c["support_status"]
            css = "ok" if st == "OK" else ("soon" if st == "SOON" else ("eol" if st == "EOL" else "unk"))
            html.append(
                "<tr>"
                f"<td>{esc(c.get('name'))}</td>"
                f"<td>{esc(c.get('product'))}</td>"
                f"<td>{esc(c.get('version'))}</td>"
                f"<td>{esc(c.get('eol_date') or '')}</td>"
                f"<td class='{css}'><b>{esc(st)}</b></td>"
                "</tr>"
            )
        html.append("</tbody></table></body></html>")

        Path(out_path).write_text("\n".join(html), encoding="utf-8")
        return {"counts": counts, "html_report": out_path}

    # ========== Public entrypoints ==========
    def run_action(self, action: str, **kwargs: Any) -> ModuleResult:
        started = datetime.now().isoformat(timespec="seconds")
        today = date.today()
        soon_days = int(_env("NTL_EOL_SOON_DAYS", "180") or "180")

        try:
            if action == "scan_range":
                cidr = str(kwargs.get("cidr", "")).strip()
                inv, stats = self._scan_range(cidr)
                return ModuleResult(
                    module="obsolescence",
                    status="SUCCESS",
                    summary=f"Scan terminé ({stats.get('found_hosts')} hôtes)",
                    details={"action": "scan_range", "stats": stats, "inventory": inv},
                    artifacts={},
                    started_at=started,
                ).finish()

            if action == "list_versions_eol":
                product = str(kwargs.get("product", "")).strip().lower()
                rows, meta = self._list_versions_eol(product)
                # enrich rows with support status (based on eol field)
                out_rows = []
                for r in rows:
                    st, eol_date = _status_from_eol(today, r.get("eol"), soon_days)
                    rr = dict(r)
                    rr["support_status"] = st
                    rr["eol_date"] = eol_date
                    out_rows.append(rr)

                status = "SUCCESS"
                if any(x["support_status"] == "EOL" for x in out_rows):
                    status = "WARNING"

                return ModuleResult(
                    module="obsolescence",
                    status=status,
                    summary=f"EOL list: {product} ({len(out_rows)} cycles)",
                    details={"action": "list_versions_eol", "product": product, "rows": out_rows, "meta": meta.__dict__},
                    artifacts={},
                    started_at=started,
                ).finish()

            if action == "csv_to_report":
                csv_path = str(kwargs.get("csv_path", "")).strip()
                do_scan = bool(kwargs.get("do_scan", False))
                cidr = str(kwargs.get("cidr", "")).strip()

                components_src = self._read_components_csv(csv_path)

                # group by product and fetch cycles
                meta_by_product: Dict[str, EOLMeta] = {}
                cache_rows: Dict[str, List[Dict[str, Any]]] = {}
                for item in components_src:
                    prod = item["product"]
                    if prod not in cache_rows:
                        rows, meta = self._list_versions_eol(prod)
                        cache_rows[prod] = rows
                        meta_by_product[prod] = meta

                # compute status per component
                components: List[Dict[str, Any]] = []
                for item in components_src:
                    prod = item["product"]
                    version = item["version"]
                    rows = cache_rows.get(prod, [])
                    match = self._match_cycle(rows, version)
                    eol_val = match.get("eol") if match else None
                    st, eol_date = _status_from_eol(today, eol_val, soon_days)
                    components.append(
                        {
                            "name": item["name"],
                            "product": prod,
                            "version": version,
                            "support_status": st,
                            "eol_date": eol_date,
                        }
                    )

                inventory: Optional[List[Dict[str, Any]]] = None
                scan_info = {"enabled": False, "cidr": "", "inventory_count": 0}
                if do_scan and cidr:
                    inv, _stats = self._scan_range(cidr)
                    inventory = inv
                    scan_info = {"enabled": True, "cidr": cidr, "inventory_count": len(inv)}

                out_html = "reports/audit/audit_report.html"
                report = self._generate_html_report(
                    inventory=inventory,
                    components=components,
                    out_path=out_html,
                    meta_by_product=meta_by_product,
                    soon_days=soon_days,
                )

                # status = WARNING if EOL present
                counts = report.get("counts", {}) or {}
                status = "SUCCESS"
                if counts.get("EOL", 0) > 0:
                    status = "WARNING"

                artifacts = {"html_report": out_html}
                return ModuleResult(
                    module="obsolescence",
                    status=status,
                    summary="Rapport HTML généré",
                    details={
                        "action": "csv_to_report",
                        "csv_path": csv_path,
                        "scan": scan_info,
                        "report": report,
                    },
                    artifacts=artifacts,
                    started_at=started,
                ).finish()

            return ModuleResult(
                module="obsolescence",
                status="ERROR",
                summary=f"Action inconnue: {action}",
                details={"action": action, "kwargs": kwargs},
                artifacts={},
                started_at=started,
            ).finish()

        except Exception as e:
            return ModuleResult(
                module="obsolescence",
                status="ERROR",
                summary="Audit obsolescence: exception",
                details={"action": action, "error": str(e), "kwargs": kwargs},
                artifacts={},
                started_at=started,
            ).finish()

    def run(self) -> ModuleResult:
        # menu interactif
        while True:
            ch = self._menu()
            if ch == "0":
                return ModuleResult(
                    module="obsolescence",
                    status="SUCCESS",
                    summary="Retour menu",
                    details={"action": "interactive"},
                    artifacts={},
                    started_at=datetime.now().isoformat(timespec="seconds"),
                ).finish()

            if ch == "1":
                cidr = _prompt("CIDR (ex: 192.168.10.0/24)", self.config.get("networks", {}).get("siege", "192.168.10.0/24"))
                return self.run_action("scan_range", cidr=cidr)

            if ch == "2":
                product = _prompt("Produit (ex: ubuntu, debian, windows, mysql, python)", "ubuntu").lower().strip()
                return self.run_action("list_versions_eol", product=product)

            if ch == "3":
                csv_path = _prompt("Chemin CSV (colonnes: product/os + version)", "inventory.csv")
                do_scan = _prompt("Activer scan réseau ? (y/N)", "n").lower() == "y"
                cidr = ""
                if do_scan:
                    cidr = _prompt("CIDR (ex: 192.168.10.0/24)", self.config.get("networks", {}).get("siege", "192.168.10.0/24"))
                return self.run_action("csv_to_report", csv_path=csv_path, do_scan=do_scan, cidr=cidr)

            print("Choix invalide.")
