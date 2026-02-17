# src/ntlsystoolbox/cli.py
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List

from ntlsystoolbox.modules import (
    AuditObsolescenceModule,
    BackupWMSModule,
    DiagnosticModule,
    ModuleResult,
    print_result,
    save_json_report,
)

__version__ = "1.0.0"


# ============================================================
# UI (ANSI) – style premium
# ============================================================
def _isatty() -> bool:
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


def _env_true(name: str) -> bool:
    v = os.getenv(name, "").strip().lower()
    return v in ("1", "true", "yes", "y", "on")


@dataclass
class UI:
    color: bool = True
    use_256: bool = True

    def __post_init__(self) -> None:
        if os.getenv("NO_COLOR"):
            self.color = False
        if not _isatty():
            self.color = False
        term = os.getenv("TERM", "")
        if "256color" not in term and "xterm" not in term:
            self.use_256 = False

    def clear(self) -> None:
        os.system("cls" if os.name == "nt" else "clear")

    def _wrap(self, s: str, code: str) -> str:
        if not self.color:
            return s
        return f"\033[{code}m{s}\033[0m"

    def bold(self, s: str) -> str:
        return self._wrap(s, "1")

    def dim(self, s: str) -> str:
        return self._wrap(s, "2")

    def red(self, s: str) -> str:
        return self._wrap(s, "31")

    def green(self, s: str) -> str:
        return self._wrap(s, "32")

    def yellow(self, s: str) -> str:
        return self._wrap(s, "33")

    def cyan(self, s: str) -> str:
        return self._wrap(s, "36")

    def gray(self, s: str) -> str:
        return self._wrap(s, "90")

    def c256(self, s: str, color_256: int) -> str:
        if not self.color or not self.use_256:
            return s
        return f"\033[38;5;{color_256}m{s}\033[0m"

    def hr(self) -> None:
        print(self.dim("─" * 74))

    def badge(self, label: str, tone: str = "info") -> str:
        if not self.color:
            return f"[{label}]"
        if tone == "success":
            return self.c256(f" {label} ", 48)
        if tone == "warn":
            return self.c256(f" {label} ", 214)
        if tone == "error":
            return self.c256(f" {label} ", 196)
        if tone == "neutral":
            return self.c256(f" {label} ", 245)
        return self.c256(f" {label} ", 39)

    def title_block(self, version: str, cfg_hint: str, non_interactive: bool) -> None:
        lines = [
            "███╗   ██╗████████╗██╗         ███████╗██╗   ██╗███████╗████████╗ ██████╗  ██████╗ ██╗     ██████╗  ██████╗ ██╗  ██╗",
            "████╗  ██║╚══██╔══╝██║         ██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔══██╗██╔═══██╗╚██╗██╔╝",
            "██╔██╗ ██║   ██║   ██║         ███████╗ ╚████╔╝ ███████╗   ██║   ██║   ██║██║   ██║██║     ██████╔╝██║   ██║ ╚███╔╝ ",
            "██║╚██╗██║   ██║   ██║         ╚════██║  ╚██╔╝  ╚════██║   ██║   ██║   ██║██║   ██║██║     ██╔══██╗██║   ██║ ██╔██╗ ",
            "██║ ╚████║   ██║   ███████╗    ███████║   ██║   ███████║   ██║   ╚██████╔╝╚██████╔╝███████╗██████╔╝╚██████╔╝██╔╝ ██╗",
            "╚═╝  ╚═══╝   ╚═╝   ╚══════╝    ╚══════╝   ╚═╝   ╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝",
        ]
        if self.color and self.use_256:
            palette = [39, 45, 51, 87, 123, 159]
            for i, ln in enumerate(lines):
                print(self.c256(ln, palette[i % len(palette)]))
        else:
            print("\n".join(lines))

        self.hr()
        ni = self.badge("NON-INTERACTIVE", "warn") if non_interactive else self.badge("INTERACTIVE", "success")
        print(
            f"{self.bold('NTL SysToolbox')} {self.dim('•')} v{version} {ni} "
            f"{self.badge('JSON reports', 'neutral')} {self.dim('→')} {cfg_hint}"
        )
        self.hr()


_UI = UI()


# ============================================================
# Defaults (MSPR)
# ============================================================
DEFAULTS: Dict[str, Any] = {
    "infrastructure": {
        "dc01_ip": "192.168.10.10",
        "dc02_ip": "192.168.10.11",
        "wms_db_ip": "192.168.10.21",
        "wms_app_ip": "192.168.10.22",
        "supervision_ip": "192.168.10.50",
        "ipbx_ip": "192.168.10.40",
    },
    "networks": {
        "siege": "192.168.10.0/24",
        "wh1": "192.168.20.0/24",
        "wh2": "192.168.30.0/24",
        "wh3": "192.168.40.0/24",
        "cdk": "192.168.50.0/24",
    },
    "database": {
        "host": "192.168.10.21",
        "port": 3306,
        "user": "root",
        "password": "",
        "name": "wms",
        "table": "",
    },
    "thresholds": {"cpu_warn": 90, "ram_warn": 90, "disk_warn": 90},
}


# ============================================================
# Config loader
# ============================================================
def _load_config(path: Optional[str]) -> Tuple[Dict[str, Any], str]:
    try:
        import yaml  # type: ignore
    except Exception:
        return {}, "(pyyaml manquant)"

    candidates: List[str] = []
    if path:
        candidates.append(path)
    env_path = os.getenv("NTL_CONFIG")
    if env_path:
        candidates.append(env_path)

    candidates += [
        "config/config.yml",
        "config.yml",
        "config/config.yaml",
        "config.yaml",
        "config.example.yml",
        "config/config.example.yml",
    ]

    for p in candidates:
        if p and os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                return (data if isinstance(data, dict) else {}), p
            except Exception:
                return {}, p

    return {}, "(aucun fichier config trouvé)"


def _merge_defaults(cfg: Dict[str, Any]) -> Dict[str, Any]:
    out = json.loads(json.dumps(DEFAULTS))  # deep copy
    for k, v in (cfg or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k].update(v)
        else:
            out[k] = v
    return out


# ============================================================
# Reports browsing
# ============================================================
def _list_reports(limit: int = 10) -> List[Path]:
    p = Path("reports/json")
    if not p.exists():
        return []
    return sorted(p.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]


def _pause(msg: str = "Appuie sur Entrée pour continuer…") -> None:
    try:
        input(_UI.dim(msg))
    except KeyboardInterrupt:
        print()


def _show_reports() -> None:
    _UI.clear()
    _UI.title_block(version=__version__, cfg_hint=str(Path("reports/json").resolve()), non_interactive=_env_true("NTL_NON_INTERACTIVE"))

    print(_UI.bold("Derniers rapports JSON"))
    print()

    files = _list_reports(12)
    if not files:
        print(_UI.yellow("Aucun rapport trouvé (reports/json/*.json).\nLance un module d’abord."))
        _pause()
        return

    for i, f in enumerate(files, 1):
        ts = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        print(f" {_UI.bold(str(i).rjust(2))} {_UI.c256(ts, 245)} {_UI.cyan(f.name)}")

    _UI.hr()
    idx = input("Ouvrir un fichier (numéro) ou Entrée pour retour > ").strip()
    if not idx:
        return
    try:
        n = int(idx)
        target = files[n - 1]
    except Exception:
        print(_UI.yellow("Numéro invalide."))
        _pause()
        return

    print()
    print(_UI.bold(f"Contenu (aperçu) : {target.name}"))
    _UI.hr()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
        text = json.dumps(data, indent=2, ensure_ascii=False)
        print(text[:4000])
        if len(text) > 4000:
            print(_UI.dim("\n(aperçu tronqué)"))
    except Exception as e:
        print(_UI.red(f"Impossible de lire JSON: {e}"))

    _pause()


# ============================================================
# Config wizard
# ============================================================
def _config_wizard(cfg_path_hint: str) -> None:
    _UI.clear()
    _UI.title_block(version=__version__, cfg_hint=cfg_path_hint, non_interactive=_env_true("NTL_NON_INTERACTIVE"))
    print(_UI.bold("Config Wizard (rapide)"))
    print(_UI.dim("Génère/écrase un fichier config YAML minimal pour éviter les prompts."))
    _UI.hr()

    target = "config/config.yml"
    overwrite = input("Écraser si existe ? (y/N) > ").strip().lower() == "y"
    p = Path(target)
    if p.exists() and not overwrite:
        print(_UI.yellow(f"{target} existe déjà. Annulé."))
        _pause()
        return

    cfg = json.loads(json.dumps(DEFAULTS))
    Path("config").mkdir(parents=True, exist_ok=True)

    # On écrit un YAML “simple” (sans dépendre d’un dumper avancé)
    # Si pyyaml est dispo, on l’utilise, sinon on écrit un YAML minimal à la main.
    try:
        import yaml  # type: ignore

        with open(target, "w", encoding="utf-8") as f:
            yaml.safe_dump(cfg, f, sort_keys=False, allow_unicode=True)
    except Exception:
        # fallback yaml minimal
        def w(line: str) -> None:
            lines.append(line)

        lines: List[str] = []
        w("infrastructure:")
        for k, v in cfg["infrastructure"].items():
            w(f"  {k}: {v}")
        w("networks:")
        for k, v in cfg["networks"].items():
            w(f"  {k}: {v}")
        w("database:")
        for k, v in cfg["database"].items():
            if isinstance(v, str):
                w(f"  {k}: '{v}'")
            else:
                w(f"  {k}: {v}")
        w("thresholds:")
        for k, v in cfg["thresholds"].items():
            w(f"  {k}: {v}")
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(_UI.green(f"OK: {target} généré."))
    _pause()


# ============================================================
# About screen
# ============================================================
def _about_screen(cfg_path: str) -> None:
    _UI.clear()
    _UI.title_block(version=__version__, cfg_hint=cfg_path, non_interactive=_env_true("NTL_NON_INTERACTIVE"))
    print(_UI.bold("À propos / Infos runtime"))
    print()
    info = {
        "OS": f"{platform.system()} {platform.release()}",
        "Python": sys.version.split()[0],
        "Repo": str(Path.cwd()),
        "Config": cfg_path,
        "Reports": str(Path("reports/json").resolve()),
        "NTL_NON_INTERACTIVE": os.getenv("NTL_NON_INTERACTIVE", "(unset)"),
    }
    for k, v in info.items():
        print(f" {_UI.c256(k + ':', 245)} {v}")

    _UI.hr()
    print(_UI.bold("Rappels MSPR (sorties attendues)"))
    print(_UI.dim("• sorties lisibles + JSON horodaté + codes retour supervisables"))
    print(_UI.dim("• menu CLI interactif + collecte des arguments nécessaires"))
    _UI.hr()
    _pause()


# ============================================================
# Run modules + render result
# ============================================================
def _handle_result(result: ModuleResult, *, json_only: bool, quiet: bool, verbose: bool) -> int:
    json_path = save_json_report(result)
    print_result(result, json_path=json_path, json_only=json_only, quiet=quiet, verbose=verbose)
    return int(result.exit_code or 0)


# ============================================================
# Menu “de fou” (mêmes entrées que ton repo)
# ============================================================
def _menu_loop(cfg: Dict[str, Any], cfg_path: str) -> int:
    while True:
        _UI.clear()
        _UI.title_block(version=__version__, cfg_hint=cfg_path, non_interactive=_env_true("NTL_NON_INTERACTIVE"))

        print(_UI.bold("Menu principal"))
        print()
        print(f" {_UI.bold('1')}  Diagnostic (AD/DNS/MySQL)")
        print(f" {_UI.bold('2')}  Backup WMS (SQL + CSV)")
        print(f" {_UI.bold('3')}  Audit Obsolescence")
        print(f" {_UI.bold('4')}  Voir rapports JSON")
        print(f" {_UI.bold('5')}  Config Wizard (générer config/config.yml)")
        print(f" {_UI.bold('6')}  About")
        print()
        print(f" {_UI.bold('q')}  Quitter")
        _UI.hr()

        choice = input("Votre choix > ").strip().lower()

        if choice == "1":
            res = DiagnosticModule(cfg).run()
            code = _handle_result(res, json_only=False, quiet=False, verbose=True)
            _pause()
            # on continue le menu
            continue

        if choice == "2":
            res = BackupWMSModule(cfg).run()
            code = _handle_result(res, json_only=False, quiet=False, verbose=True)
            _pause()
            continue

        if choice == "3":
            res = AuditObsolescenceModule(cfg).run()
            # si l’utilisateur choisit “retour menu”, on ne force pas un résultat “utile”
            # mais on génère quand même un JSON (preuve)
            code = _handle_result(res, json_only=False, quiet=False, verbose=True)
            _pause()
            continue

        if choice == "4":
            _show_reports()
            continue

        if choice == "5":
            _config_wizard(cfg_path)
            # reload config after wizard
            new_cfg, new_path = _load_config(None)
            cfg.clear()
            cfg.update(_merge_defaults(new_cfg))
            cfg_path = new_path
            continue

        if choice == "6":
            _about_screen(cfg_path)
            continue

        if choice == "q":
            return 0

        print(_UI.yellow("Choix invalide."))
        _pause()


# ============================================================
# Argparse mode (optionnel) — utile pour scripts + CI
# ============================================================
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ntl-systoolbox")
    p.add_argument("--config", default=None, help="Chemin config yml (optionnel)")
    p.add_argument("--json-only", action="store_true", help="Affiche uniquement le chemin du JSON")
    p.add_argument("--quiet", action="store_true", help="Sortie compacte")
    p.add_argument("--verbose", action="store_true", help="Détails")
    p.add_argument("--non-interactive", action="store_true", help="Désactive les prompts (NTL_NON_INTERACTIVE=1)")
    p.add_argument("--menu", action="store_true", help="Force le menu interactif")

    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("diagnostic")
    sub.add_parser("backup-wms")

    obs = sub.add_parser("audit-obsolescence")
    obs_sub = obs.add_subparsers(dest="action")
    obs_sub.add_parser("interactive")

    p_scan = obs_sub.add_parser("scan-range")
    p_scan.add_argument("--cidr", required=True)

    p_list = obs_sub.add_parser("list-eol")
    p_list.add_argument("--product", required=True)

    p_csv = obs_sub.add_parser("csv-report")
    p_csv.add_argument("--csv", required=True)
    p_csv.add_argument("--scan", action="store_true")
    p_csv.add_argument("--cidr", default="")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    ns = _build_parser().parse_args(argv)

    if ns.non_interactive:
        os.environ["NTL_NON_INTERACTIVE"] = "1"

    cfg_raw, cfg_path = _load_config(ns.config)
    cfg = _merge_defaults(cfg_raw)

    # Menu par défaut si aucune cmd (même comportement que ton usage “ntl-systoolbox”)
    if ns.menu or not ns.cmd:
        return _menu_loop(cfg, cfg_path)

    # Mode sous-commandes
    if ns.cmd == "diagnostic":
        res = DiagnosticModule(cfg).run()
    elif ns.cmd == "backup-wms":
        res = BackupWMSModule(cfg).run()
    elif ns.cmd == "audit-obsolescence":
        m = AuditObsolescenceModule(cfg)
        action = ns.action or "interactive"
        if action in (None, "interactive"):
            res = m.run()
        elif action == "scan-range":
            res = m.run_action("scan_range", cidr=ns.cidr)
        elif action == "list-eol":
            res = m.run_action("list_versions_eol", product=ns.product)
        elif action == "csv-report":
            res = m.run_action("csv_to_report", csv_path=ns.csv, do_scan=bool(ns.scan), cidr=ns.cidr)
        else:
            res = ModuleResult(module="obsolescence", status="ERROR", summary=f"Action inconnue: {action}").finish()
    else:
        res = ModuleResult(module="tool", status="ERROR", summary=f"Commande inconnue: {ns.cmd}").finish()

    json_path = save_json_report(res)
    print_result(res, json_path=json_path, json_only=ns.json_only, quiet=ns.quiet, verbose=ns.verbose)
    return int(res.exit_code or 0)


if __name__ == "__main__":
    raise SystemExit(main())
