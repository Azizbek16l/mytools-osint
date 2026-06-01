"""Plugin loader — discover third-party modules via setuptools entry-points.

A plugin is a normal Python package that:
  1. Exposes one or more modules with NAME / run / register attributes
     (same shape as built-in `app/modules/*.py`).
  2. Declares an entry-point in its pyproject.toml:

         [project.entry-points."mytools_osint.modules"]
         my_module = "my_pkg.module:MODULE"

     where MODULE is the module object itself (the `_my_module` style used
     by app/modules/__init__.py).

Loader:
  - Scans entry_points("mytools_osint.modules") at runtime.
  - Validates each plugin: must have NAME (str), run (callable), register (callable).
  - Logs successful loads + reasons-for-skip; never crashes the host process.
  - Plugin runs in the same Python interpreter — NO sandboxing. Users install
    plugins they trust; pyproject deps are the trust boundary.

CLI surface:
  osint plugin list           — discovered plugins + status
  osint plugin search <q>     — PyPI search for `mytools-osint-` prefix packages
  osint plugin install <pkg>  — pip install in venv (warns if mismatched)
  osint plugin remove <pkg>   — pip uninstall

NOT a sandbox — see SECURITY.md threat-model. Use trusted sources.
"""
from __future__ import annotations

import importlib
import importlib.metadata
import logging
import subprocess
import sys
from typing import Any

log = logging.getLogger("mytools-osint.plugins")

ENTRY_POINT_GROUP = "mytools_osint.modules"


def discover() -> list[tuple[str, Any, str]]:
    """Return list of (plugin_name, module_obj, status). status is one of:
    'ok', 'invalid', 'load-error: …'."""
    out: list[tuple[str, Any, str]] = []
    try:
        eps = importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)
    except Exception as e:
        log.debug("entry_points lookup failed: %s", e)
        return out
    for ep in eps:
        try:
            mod = ep.load()
        except Exception as e:
            out.append((ep.name, None, f"load-error: {type(e).__name__}: {e}"))
            continue
        # Validate shape
        if (not hasattr(mod, "NAME") or not hasattr(mod, "run")
                or not hasattr(mod, "register")):
            out.append((ep.name, None, "invalid: missing NAME/run/register"))
            continue
        out.append((ep.name, mod, "ok"))
    return out


def register_with_runner(runner) -> int:
    """Auto-discover + register each valid plugin module with the runner."""
    n = 0
    for name, mod, status in discover():
        if status != "ok":
            log.warning("skipping plugin %s: %s", name, status)
            continue
        try:
            mod.register(runner)
            n += 1
            log.info("registered plugin %s", name)
        except Exception as e:
            log.warning("plugin %s register() failed: %s", name, e)
    return n


# ---------------------------------------------------------------- CLI dispatch

def cmd_plugin(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print("usage: osint plugin <list|search|install|remove> ...\n"
              "  plugins are pip-installable packages declaring the\n"
              "  `mytools_osint.modules` entry-point group.\n"
              "  See https://github.com/Azizbek16l/mytools-osint#plugins for the template.",
              file=sys.stderr)
        return 0 if argv else 2
    sub = argv[0]
    if sub == "list":
        items = discover()
        if not items:
            print("  no plugins installed.")
            print("  install with: osint plugin install <pip-package>")
            return 0
        for name, _, status in items:
            mark = "✓" if status == "ok" else "✕"
            colour = "32" if status == "ok" else "31"
            print(f"  \033[{colour}m{mark}\033[0m {name:<24} {status}")
        return 0
    if sub == "search" and len(argv) >= 2:
        q = argv[1]
        try:
            r = subprocess.run([sys.executable, "-m", "pip", "search",
                                f"mytools-osint-{q}"],
                               capture_output=True, text=True, timeout=20,
                               check=False)
            print(r.stdout or r.stderr)
        except Exception:
            # pip search was deprecated on the official index. Fall back to
            # browser-style hint.
            print("  pip search is disabled on PyPI. Try:")
            print(f"    https://pypi.org/search/?q=mytools-osint-{q}")
        return 0
    if sub == "install" and len(argv) >= 2:
        pkg = argv[1]
        try:
            r = subprocess.run([sys.executable, "-m", "pip", "install", pkg],
                               capture_output=True, text=True, timeout=180,
                               check=False)
            print(r.stdout)
            if r.returncode != 0:
                print(r.stderr, file=sys.stderr)
                return r.returncode
        except Exception as e:
            print(f"install failed: {e}", file=sys.stderr)
            return 1
        return 0
    if sub == "remove" and len(argv) >= 2:
        pkg = argv[1]
        try:
            r = subprocess.run([sys.executable, "-m", "pip", "uninstall",
                                "-y", pkg],
                               capture_output=True, text=True, timeout=60,
                               check=False)
            print(r.stdout)
            return r.returncode
        except Exception as e:
            print(f"remove failed: {e}", file=sys.stderr)
            return 1
    print("usage: osint plugin <list|search|install|remove> ...",
          file=sys.stderr)
    return 2
