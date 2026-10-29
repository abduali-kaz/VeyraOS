#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "=== Building Veyra Core ==="
cargo build --release

echo "=== Copying Veyra into ISO profile ==="
install -Dm755 target/release/veyra \
    iso/profile/airootfs/usr/local/bin/veyra

echo "=== Building Veyra ISO ==="
sudo mkarchiso -v \
    -w "$ROOT/work" \
    -o "$ROOT/out" \
    "$ROOT/iso/profile"

echo "=== ISO files ==="
ls -lh "$ROOT/out"
