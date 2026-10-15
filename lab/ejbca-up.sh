#!/usr/bin/env bash
# Starts EJBCA Community Edition in podman (simple TLS setup; lab only). Needs ~4 GB VM memory:
#   podman machine set --memory 6144
# Admin UI: https://localhost:8443/ejbca/adminweb/ (client cert required) ; public: https://localhost:8442/ejbca/
podman rm -f pkisage-ejbca >/dev/null 2>&1 || true
podman run -d --name pkisage-ejbca -p 8080:8080 -p 8442:8442 -p 8443:8443 \
  -e TLS_SETUP_ENABLED="simple" docker.io/keyfactor/ejbca-ce:latest
