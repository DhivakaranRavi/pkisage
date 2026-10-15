#!/usr/bin/env bash
# Checks the metrics unit files on Rocky Linux 9 (podman): unit syntax via systemd-analyze, and runs
# the service's ExecStart command for real against the system CA bundle.
set -euo pipefail
cd "$(dirname "$0")/.."
podman run --rm -v "$PWD":/src:ro docker.io/rockylinux/rockylinux:9 bash -c '
  set -euo pipefail
  dnf -y -q install python3.12 python3.12-pip systemd >/dev/null 2>&1
  mkdir /work && cd /work && tar -C /src --exclude=.venv --exclude=lab --exclude=.env --exclude=model.md --exclude=.git -cf - . | tar xf -
  python3.12 -m venv /opt/pkisage && /opt/pkisage/bin/pip -q install . 2>&1 | grep -v "^\[notice\]" || true
  mkdir -p /var/lib/node_exporter/textfile_collector
  cp deploy/pkisage-metrics.service deploy/pkisage-metrics.timer /etc/systemd/system/
  echo "--- systemd-analyze verify"
  systemd-analyze verify /etc/systemd/system/pkisage-metrics.service /etc/systemd/system/pkisage-metrics.timer && echo "units OK"
  echo "--- run ExecStart"
  sh -c "$(grep ^ExecStart= deploy/pkisage-metrics.service | sed "s/^ExecStart=//")"
  ls -la /var/lib/node_exporter/textfile_collector/
  grep -c "^pkisage_cert_expiry_days" /var/lib/node_exporter/textfile_collector/pkisage.prom
'
