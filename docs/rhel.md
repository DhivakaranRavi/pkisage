# Installing on RHEL-compatible systems

Tested on **Rocky Linux 9.8** (RHEL 9 compatible) using `deploy/rhel-test.sh` (podman). Not tested on RHEL itself or on RHEL 8.

```
dnf install -y python3.12 python3.12-pip openssl
python3.12 -m venv /opt/pkisage
/opt/pkisage/bin/pip install pkisage        # or: pip install .  from a checkout
/opt/pkisage/bin/pkisage --version
```

`deploy/rhel-test.sh` installs from the working tree in a clean Rocky 9 container, then runs `--version`, `preflight` and `explain`. It found and led to the fix of a packaging bug that an editable install had hidden.

## Optional: certificate expiry metrics (Prometheus node_exporter textfile collector)
`deploy/pkisage-metrics.service` and `deploy/pkisage-metrics.timer` write `pkisage metrics` output hourly to the textfile-collector directory. The units pass `systemd-analyze verify` and the service's command was run on Rocky 9 (`deploy/systemd-test.sh`, 146 certificates exported); **the timer was not run under a live systemd**. Review paths (`/etc/pki/tls/certs`, `/var/lib/node_exporter/textfile_collector`) for your host. The `metrics --serve PORT` endpoint was verified with a real HTTP scrape.

## Notes
- Configure AI providers via `.env` or the service environment; never commit secrets. Use a local model (Ollama) if data must not leave the host.
- Run as an unprivileged user; pkisage only needs read access to the certificate files.
