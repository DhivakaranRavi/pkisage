#!/usr/bin/env bash
# Starts a local Pebble ACME test CA on https://127.0.0.1:14000/dir (challenges auto-pass).
# Download the binary from https://github.com/letsencrypt/pebble/releases into lab/bin first.
cd "$(dirname "$0")/.." || exit 1
BIN=$(ls lab/bin/pebble-*/*/*/pebble 2>/dev/null | head -1)
[ -x "$BIN" ] || { echo "pebble binary not found in lab/bin"; exit 1; }
PEBBLE_VA_ALWAYS_VALID=1 PEBBLE_VA_NOSLEEP=1 exec "$BIN" -config lab/pebble-config.json
