# Security policy

Correlic is a security tool, so reports about Correlic itself get priority.

## Supported versions

Only the latest release on the `main` branch receives fixes.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private
vulnerability reporting on this repository ("Security" tab → "Report a
vulnerability"). Include the version, the component (backend, agent, dashboard,
proxy, installer), reproduction steps and the impact you believe it has.

You will get an acknowledgement within 72 hours and a fix or a mitigation plan
within 14 days for confirmed issues. Credit is given in the release notes unless
you prefer otherwise.

## Deployment notes

- The dashboard and the ui-proxy bind to localhost by default. Put a reverse
  proxy with TLS and authentication in front of them before exposing them.
- The agent runs as root and loads eBPF programs; only install it on hosts you
  administer.
- Every install creates two credentials: a dashboard admin (API key and
  password) and a restricted agent key. Never put the dashboard key in
  `agent.yaml`.
- All data stays on the machines you run Correlic on. There is no telemetry to
  the project.
