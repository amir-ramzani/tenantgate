#!/usr/bin/env python3
"""Export the OpenAPI documents of the control plane and the demo API.

Writes ``docs/openapi/control-plane.json`` and ``docs/openapi/demo-api.json``.
Schema generation only inspects routes and models: no AWS access or
configuration is needed.

    python scripts/export_openapi.py           # regenerate
    python scripts/export_openapi.py --check   # exit 1 if the files are stale (CI)
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "openapi"
sys.path.insert(0, str(ROOT / "src"))


def _no_deps() -> NoReturn:
    raise RuntimeError("dependencies are not available while exporting the schema")


def specs() -> dict[str, dict[str, Any]]:
    from control_plane.app import create_app as control_plane_app
    from demo_api.app import create_app as demo_app

    factories: dict[str, Callable[..., Any]] = {
        "control-plane.json": control_plane_app,
        "demo-api.json": demo_app,
    }
    return {name: factory(_no_deps).openapi() for name, factory in factories.items()}


def render(spec: dict[str, Any]) -> str:
    return json.dumps(spec, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if committed files are stale")
    args = ap.parse_args()

    stale = []
    for name, spec in specs().items():
        path = OUT / name
        text = render(spec)
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(path.relative_to(ROOT))
        else:
            OUT.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
    if stale:
        print("stale OpenAPI files (run scripts/export_openapi.py):", *stale, sep="\n  ")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
