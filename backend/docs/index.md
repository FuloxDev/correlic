# Correlic documentation

Correlic is an open-source runtime security monitor for AI coding agents. A
kernel-level host agent (eBPF on Linux, ETW on Windows, Endpoint Security via
`eslogger` on macOS) records what Claude Code, Cursor, Copilot, aider and
similar tools actually do (processes, files, network, DNS), keeps the activity
attributed to the AI process tree, and ships it to a backend that runs
detection rules, correlates multi-step attack chains into incidents and lets
you investigate them with your own LLM key. Everything runs on your own
infrastructure.

Start with the [system reference](SYSTEM_REFERENCE.md), then the
[architecture](ARCHITECTURE.md) and the [detection engine](DETECTION_ENGINE.md).
The source, installers and release notes live in the
[GitHub repository](https://github.com/FuloxDev/correlic).

## Where to look

| Question | Document |
|---|---|
| How does the whole system fit together? | [System reference](SYSTEM_REFERENCE.md), [Architecture](ARCHITECTURE.md) |
| What does the Linux agent capture and how? | [Linux agent](LINUX_AGENT.md) |
| What about Windows and macOS? | [Windows agent](WINDOWS_AGENT.md), [macOS agent](MACOS_AGENT.md) |
| How do I see every command Claude Code or Cursor runs? | [AI tool hooks](HOOKS.md) |
| Which rules exist and when do they fire? | [Detection engine](DETECTION_ENGINE.md), [Suspicious file reference](suspicious-files-reference.md) |
| How are findings turned into incidents? | [Incident engine](INCIDENT_ENGINE.md), [Correlation engine](CORRELATION_ENGINE.md) |
| How does alerting work? | [Alerting](ALERT_ENGINE.md) |
| What is the API? | [API reference](API_REFERENCE.md) |
| What is the research behind it? | [Paper](paper/correlic-paper.md) |
