# src/ntlsystoolbox/cli.py
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Import robuste : marche en package ET en exécution locale
try:
    from ntlsystoolbox.modules import (  # type: ignore
        AuditObsolescenceModule,
        BackupWMSModule,
        DiagnosticModule,
        ModuleResult,
        print_result,
        save_json_report,
    )
except ImportError:
    try:
        from modules import (  # type: ignore
            AuditObsolescenceModule,
            BackupWMSModule,
            DiagnosticModule,
            ModuleResult,
            print_result,
            save_json_report,
        )
    except ImportError as e:
        raise ImportError(
            "Impossible d'importer ntlsystoolbox.modules. "
            "Vérifie PYTHONPATH=src ou installe le package (pip install -e .)."
        ) from e

__version__ = "1.0.0"


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
        try:
            os.system("cls" if os.name == "nt" else "clear")
        except Exception:
            pass

    def _wrap(self, s: str, code: str) -> str:
        if not self.color:
            return s
        return f"\033[{code}m{s}\033[0m"

    def bold(self, s: str) -> str:
        return self._wrap(s, "1")

    def dim(self, s: str) -> str:
        return self._wrap(s, "2")

    def yellow(self, s: str) -> str:
        return self._wrap(s, "33")

    def cyan(self, s: str) -> str:
        return self._wrap(s, "36")

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

DEFAULTS: Dict[str, Any] = {
    "infrastructure": {
        "dc01_ip": "192.168.10.10",
        "dc02_ip": "192.168.10.11",
        "wms_db_ip": "192.168.10.21",
        "wms_app_ip": "192.168.10.22",
    },
    "networks": {"siege": "192.168.10.0/24"},
    "database": {"host": "192.168.10.21", "port": 3306, "user": "root", "password": "", "name": "wms", "table": ""},
    "thresholds": {"cpu_warn": 90, "ram_warn": 90, "disk_warn": 90},
}


def _load_config(path: Optional[str]) -> Tuple[Dict[str, Any], str]:
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
        "config/config.json",
        "config.json",
    ]

    yaml_mod = None
    try:
        import yaml  # type: ignore

        yaml_mod = yaml
    except Exception:
        yaml_mod = None

    for p in candidates:
        if p and os.path.exists(p):
            try:
                if p.endswith(".json"):
                    data = json.loads(Path(p).read_text(encoding="utf-8"))
                    return (data if isinstance(data, dict) else {}), p
                if yaml_mod is not None:
                    with open(p, "r", encoding="utf-8") as f:
                        data = yaml_mod.safe_load(f) or {}
                    return (data if isinstance(data, dict) else {}), p
            except Exception:
                return {}, p

    if yaml_mod is None:
        return {}, "(pyyaml manquant + aucun json trouvé)"
    return {}, "(aucun fichier config trouvé)"


def _merge_defaults(cfg: Dict[str, Any]) -> Dict[str, Any]:
    out = json.loads(json.dumps(DEFAULTS))
    for k, v in (cfg or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k].update(v)
        else:
            out[k] = v
    return out


def _pause(msg: str = "Appuie sur Entrée pour continuer…") -> None:
    try:
        input(_UI.dim(msg))
    except KeyboardInterrupt:
        print()


def _list_reports(limit: int = 10) -> List[Path]:
    p = Path("reports/json")
    if not p.exists():
        return []
    return sorted(p.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True)[:limit]


def _show_reports() -> None:
    _UI.clear()
    _UI.title_block(__version__, str(Path("reports/json").resolve()), _env_true("NTL_NON_INTERACTIVE"))
    print(_UI.bold("Derniers rapports JSON\n"))

    files = _list_reports(12)
    if not files:
        print(_UI.yellow("Aucun rapport trouvé (reports/json/*.json)."))
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

    print("\n" + _UI.bold(f"Contenu (aperçu) : {target.name}"))
    _UI.hr()
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
        text = json.dumps(data, indent=2, ensure_ascii=False)
        print(text[:4000])
        if len(text) > 4000:
            print(_UI.dim("\n(aperçu tronqué)"))
    except Exception as e:
        print(_UI.yellow(f"Impossible de lire JSON: {e}"))
    _pause()


def _handle_result(result: ModuleResult, *, json_only: bool, quiet: bool, verbose: bool) -> int:
    json_path = save_json_report(result)
    print_result(result, json_path=json_path, json_only=json_only, quiet=quiet, verbose=verbose)
    return int(result.exit_code or 0)


def _menu_loop(cfg: Dict[str, Any], cfg_path: str) -> int:
    while True:
        _UI.clear()
        _UI.title_block(__version__, cfg_path, _env_true("NTL_NON_INTERACTIVE"))

        print(_UI.bold("Menu principal\n"))
        print(f" {_UI.bold('1')}  Diagnostic (AD/DNS/MySQL)")
        print(f" {_UI.bold('2')}  Backup WMS (SQL + CSV)")
        print(f" {_UI.bold('3')}  Audit Obsolescence")
        print(f" {_UI.bold('4')}  Voir rapports JSON\n")
        print(f" {_UI.bold('q')}  Quitter")
        _UI.hr()

        choice = input("Votre choix > ").strip().lower()

        if choice == "1":
            res = DiagnosticModule(cfg).run()
            _handle_result(res, json_only=False, quiet=False, verbose=True)
            _pause()
            continue

        if choice == "2":
            res = BackupWMSModule(cfg).run()
            _handle_result(res, json_only=False, quiet=False, verbose=True)
            _pause()
            continue

        if choice == "3":
            res = AuditObsolescenceModule(cfg).run()
            _handle_result(res, json_only=False, quiet=False, verbose=True)
            _pause()
            continue

        if choice == "4":
            _show_reports()
            continue

        if choice == "q":
            return 0

        print(_UI.yellow("Choix invalide."))
        _pause()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ntl-systoolbox")
    p.add_argument("--config", default=None, help="Chemin config yml/json (optionnel)")
    p.add_argument("--json-only", action="store_true", help="Affiche uniquement le chemin du JSON")
    p.add_argument("--quiet", action="store_true", help="Sortie compacte")
    p.add_argument("--verbose", action="store_true", help="Détails")
    p.add_argument("--non-interactive", action="store_true", help="NTL_NON_INTERACTIVE=1")
    p.add_argument("--menu", action="store_true", help="Force le menu interactif")

    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("diagnostic")
    sub.add_parser("backup-wms")
    sub.add_parser("audit-obsolescence")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    ns = _build_parser().parse_args(argv)

    if ns.non_interactive:
        os.environ["NTL_NON_INTERACTIVE"] = "1"

    cfg_raw, cfg_path = _load_config(ns.config)
    cfg = _merge_defaults(cfg_raw)

    if ns.menu or not ns.cmd:
        return _menu_loop(cfg, cfg_path)

    if ns.cmd == "diagnostic":
        res = DiagnosticModule(cfg).run()
    elif ns.cmd == "backup-wms":
        res = BackupWMSModule(cfg).run()
    elif ns.cmd == "audit-obsolescence":
        res = AuditObsolescenceModule(cfg).run()
    else:
        res = ModuleResult(module="tool", status="ERROR", summary=f"Commande inconnue: {ns.cmd}").finish()

    json_path = save_json_report(res)
    print_result(res, json_path=json_path, json_only=ns.json_only, quiet=ns.quiet, verbose=ns.verbose)
    return int(res.exit_code or 0)


if __name__ == "__main__":
    raise SystemExit(main())
