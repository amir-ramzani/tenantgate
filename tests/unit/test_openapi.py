"""The committed OpenAPI documents must match the code."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "export_openapi.py"


def test_committed_specs_are_up_to_date() -> None:
    result = subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), "--check"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_control_plane_spec_documents_auth() -> None:
    spec = json.loads((ROOT / "docs/openapi/control-plane.json").read_text())
    assert spec["servers"][0]["url"] == "/control"
    assert spec["components"]["securitySchemes"]["bearerAuth"]["scheme"] == "bearer"
    assert "security" not in spec["paths"]["/status"]["get"]
    create = spec["paths"]["/tenants"]["post"]
    assert create["security"] == [{"bearerAuth": []}]
    assert {"401", "403", "503"} <= set(create["responses"])
    params = {p["name"].lower() for p in create.get("parameters", [])}
    assert "authorization" not in params and "idempotency-key" in params


def test_demo_spec_paths() -> None:
    spec = json.loads((ROOT / "docs/openapi/demo-api.json").read_text())
    assert set(spec["paths"]) == {
        "/health",
        "/tenants/{tenant_id}/whoami",
        "/tenants/{tenant_id}/notes",
        "/tenants/{tenant_id}/notes/{note_id}",
    }
