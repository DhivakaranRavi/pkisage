#!/usr/bin/env bash
# Starts a step-ca private CA (with ACME provisioner) in podman on https://localhost:9000
set -e
podman rm -f pkisage-step-ca >/dev/null 2>&1 || true
podman volume create pkisage-step-data >/dev/null 2>&1 || true
podman run -d --name pkisage-step-ca -p 9000:9000 \
  -e DOCKER_STEPCA_INIT_NAME="pkisage Lab CA" \
  -e DOCKER_STEPCA_INIT_DNS_NAMES="localhost,127.0.0.1" \
  -e DOCKER_STEPCA_INIT_PROVISIONER_NAME=admin \
  -e DOCKER_STEPCA_INIT_PASSWORD=lab-only-password \
  -e DOCKER_STEPCA_INIT_ACME=true \
  -v pkisage-step-data:/home/step docker.io/smallstep/step-ca:latest
