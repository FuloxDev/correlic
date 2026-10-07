#!/bin/bash
set -e
for svc in correlic-api correlic-telemetry correlic-agent correlic-ui correlic-ui-proxy; do
  systemctl stop "$svc" 2>/dev/null || true
  systemctl disable "$svc" 2>/dev/null || true
done
systemctl daemon-reload
