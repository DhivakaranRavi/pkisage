#!/usr/bin/env bash
# Verifies install + core commands on a RHEL-compatible OS (Rocky Linux 9) using podman.
set -euo pipefail
cd "$(dirname "$0")/.."
podman run --rm -v "$PWD":/src:ro docker.io/rockylinux/rockylinux:9 bash -c '
  set -euo pipefail
  dnf -y -q install python3.12 python3.12-pip openssl >/dev/null
  mkdir /work && cd /work && tar -C /src --exclude=.venv --exclude=lab --exclude=.env --exclude=model.md -cf - . | tar xf -
  python3.12 -m venv /opt/pkisage && /opt/pkisage/bin/pip -q install . 2>&1 | grep -v "^\[notice\]" | tail -8 || true
  cat /etc/redhat-release
  openssl req -new -newkey rsa:1024 -nodes -keyout /dev/null -subj /CN=x.example.com -out /tmp/w.csr 2>/dev/null
  /opt/pkisage/bin/pkisage --version
  /opt/pkisage/bin/pkisage preflight /tmp/w.csr | grep -E "FAIL" || true
  /opt/pkisage/bin/pkisage explain --ca stepca --error "RSA key must be at least 2048 bits" | head -1
'
