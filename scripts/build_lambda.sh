#!/usr/bin/env bash
# Build the Lambda asset shared by every function: runtime dependencies for
# arm64 / Python 3.12 plus the packages under src/.
#
# boto3 is bundled on purpose: the managed runtime's copy can lag behind newer
# Cognito APIs (managed login branding, multi-Region replication).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/lambda"
REQ="$ROOT/build/requirements.txt"

rm -rf "$OUT"
mkdir -p "$OUT"

uv export --project "$ROOT" --frozen --no-dev --no-hashes --no-emit-project -o "$REQ"
uv pip install --quiet --requirement "$REQ" --target "$OUT" \
  --python-platform aarch64-manylinux2014 --python-version 3.12 --only-binary=:all:

for pkg in authlib_mt canary control_plane demo_api tenantgate triggers; do
  cp -R "$ROOT/src/$pkg" "$OUT/"
done

find "$OUT" -type d -name '__pycache__' -prune -exec rm -rf {} +
find "$OUT" -type d -name 'tests' -path '*/site-packages/*' -prune -exec rm -rf {} + 2>/dev/null || true
echo "lambda asset: $OUT ($(du -sh "$OUT" | cut -f1))"
