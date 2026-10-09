# Correlic macOS agent — Homebrew formula, built from source.
#
# Head-only for now:
#   brew install --HEAD ./install/homebrew/correlic-agent.rb
#   brew upgrade --fetch-HEAD correlic-agent        # rebuild from main later
#
# Why no stable block yet: Homebrew needs the sha256 of the release source
# tarball, and the latest release (v1.0.1) predates correlic-hook, which this
# formula builds. With the next release add, above `head`:
#   url "https://github.com/FuloxDev/correlic/archive/refs/tags/v<X.Y.Z>.tar.gz"
#   sha256 "<shasum -a 256 of that tarball>"
# and the `--HEAD` flag becomes optional. See README.md next to this file for
# turning it into a tap (`brew tap fuloxdev/correlic`).
class CorrelicAgent < Formula
  desc "Runtime security monitor for AI coding agents — macOS host agent and tool hook"
  homepage "https://github.com/FuloxDev/correlic"
  license "MIT"
  head "https://github.com/FuloxDev/correlic.git", branch: "main"

  depends_on "go" => :build
  depends_on :macos => :big_sur # Go 1.26 requires macOS 11+

  def install
    ldflags = "-s -w -X main.version=#{version}"
    cd "agent" do
      system "go", "build", *std_go_args(ldflags:, output: bin/"correlic-agent"), "./cmd/agent"
      system "go", "build", *std_go_args(ldflags:, output: bin/"correlic-hook"), "./cmd/correlic-hook"
    end

    # Example configuration; the real one comes from `correlic-admin bootstrap`
    # (or the installer) on the backend and is copied here with the certificates.
    (etc/"correlic").mkpath
    (etc/"correlic/agent.yaml.example").write <<~YAML
      # Correlic agent configuration (macOS). Copy to #{etc}/correlic/agent.yaml and
      # put ca.crt, client.crt and client.key next to it.
      backend_url: "https://localhost:8080"
      telemetry_url: "https://localhost:8081"
      api_key: "PASTE_AGENT_KEY_HERE"
      tls_ca_file: "#{etc}/correlic/ca.crt"
      tls_client_cert_file: "#{etc}/correlic/client.crt"
      tls_client_key_file: "#{etc}/correlic/client.key"
      profile: "developer"
      log_level: "info"
      heartbeat_interval: 30s
      eslogger_enabled: true          # Endpoint Security via /usr/bin/eslogger (macOS 13+, root, Full Disk Access)
      process_exec_enabled: true
      file_monitor_enabled: true
      network_monitor_enabled: true
      dns_monitor_enabled: true
      block_enabled: false
    YAML
  end

  # `sudo brew services start correlic-agent` — the agent must run as root.
  service do
    run [opt_bin/"correlic-agent", "--config", etc/"correlic/agent.yaml"]
    require_root true
    keep_alive true
    log_path var/"log/correlic-agent.log"
    error_log_path var/"log/correlic-agent.log"
  end

  def caveats
    <<~EOS
      correlic-agent runs as root. On macOS 13+ it gets Endpoint Security events
      (process exec/exit/fork, file opens with real PIDs) by running Apple's
      /usr/bin/eslogger, which needs Full Disk Access for the responsible
      process. Without root or that grant it falls back to kqueue/FSEvents/lsof
      polling (file events without PID attribution). `correlic-agent check-compat`
      prints which path this Mac will use.

      1. Configuration: copy the agent.yaml and certificates your backend's
         `correlic-admin bootstrap` (or installer) generated to #{etc}/correlic/
         (example: #{etc}/correlic/agent.yaml.example).

      2. Full Disk Access (System Settings > Privacy & Security > Full Disk Access):
         - foreground: add your terminal app (Terminal, iTerm, VS Code, ...), then
             sudo correlic-agent --config #{etc}/correlic/agent.yaml
         - as a service: add #{opt_bin}/correlic-agent (press Cmd-Shift-G in the
           file dialog to type the path), then
             sudo brew services start correlic-agent
         macOS ties the grant to the binary's code identity: re-check it after
         every upgrade, an unsigned rebuild can lose it.

      3. Claude Code / Cursor tool hooks (no root needed):
             correlic-hook setup
    EOS
  end

  test do
    assert_match "correlic-hook", shell_output("#{bin}/correlic-hook version")
    # A missing --config value exits 2 with the usage line; no root required.
    assert_match "usage:", shell_output("#{bin}/correlic-agent --config 2>&1", 2)
  end
end
