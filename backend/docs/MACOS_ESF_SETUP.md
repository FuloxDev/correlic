# macOS Endpoint Security setup

The macOS agent has two modes. Without Apple's Endpoint Security entitlement
it polls (kqueue for processes, FSEvents for files, lsof for connections) and
cannot say which process opened a file. With the entitlement it receives
every exec, exit, file open and DNS lookup from the kernel with the real PID,
the same quality the Linux eBPF agent delivers. The code for both modes is in
the repository; what is missing is Apple's permission, a Developer ID
signature and a provisioning profile. This runbook is the complete path from
an Apple Developer account to a signed, notarized agent that uses Endpoint
Security, and it is written to be executed step by step from a browser signed
in to the account.

What is already in the repository:

| Piece | Where |
|---|---|
| Endpoint Security client, collector and runners (exec/exit, file open, DNS) | `agent/internal/darwin/esf/` (build tag `esf`, cgo) |
| Startup wiring with automatic fallback to kqueue/FSEvents | `agent/cmd/agent/platform_darwin_esf.go` |
| Entitlements file | `agent/build/correlic-agent.entitlements` |
| App bundle `Info.plist` and launchd job | `agent/build/Info.plist`, `agent/build/com.correlic.agent.plist` |
| Build, sign, notarize, attach to release | `.github/workflows/build-macos-agent.yml` |
| Compile check of the ESF code on every PR | `agent-macos` job in `.github/workflows/ci.yml` |

An `esf`-tagged binary is safe everywhere: if the entitlement is missing, the
agent is not root, or Full Disk Access was not granted, it logs the reason and
runs the polling collectors.

## 1. Check the account first

In [developer.apple.com/account](https://developer.apple.com/account):

- **Membership details**: the Apple Developer Program must be active, and
  note the **entity type**. Apple grants the Endpoint Security entitlement
  almost exclusively to **Organization** accounts (a company with a D-U-N-S
  number). Requests from Individual accounts are usually declined. If the
  account is Individual, either enrol an organization or expect the request
  to be refused; the polling agent keeps working either way.
- **Role**: creating Developer ID certificates needs the **Account Holder**.
- **Agreements**: the Apple Developer Program License Agreement must be
  accepted (the account page shows a banner if it is not). Requests and
  profile creation are blocked until it is.

## 2. Register the identifier

Certificates, Identifiers & Profiles → Identifiers → **+** → App IDs → App:

| Field | Value |
|---|---|
| Description | `Correlic Agent` |
| Bundle ID | Explicit, `com.correlic.agent` |
| Capabilities | none for now; **Endpoint Security** appears in this list only after Apple grants it |

## 3. Request the entitlement

Open <https://developer.apple.com/contact/request/system-extension/> while
signed in. Field labels change over time; map these answers onto whatever the
form asks:

| Likely prompt | Answer |
|---|---|
| Team | the organization team |
| Entitlement / extension type | **Endpoint Security** (`com.apple.developer.endpoint-security.client`) |
| App name | Correlic Agent |
| Bundle ID | `com.correlic.agent` |
| Website | <https://github.com/FuloxDev/correlic> |
| App description | Correlic is an open-source (MIT) runtime security monitor for AI coding agents such as Claude Code, Cursor, Copilot and aider. A host agent records what those tools actually do on a developer's machine (processes they launch, files they read and write, network connections and DNS lookups), attributes each event to the AI process tree it belongs to, and sends the events to a self-hosted backend that runs detection rules (credential theft, reverse shells, persistence, data exfiltration), correlates multi-step attack chains into incidents and alerts the user. Nothing leaves the user's infrastructure. |
| Why this entitlement is needed | The product's purpose is per-process attribution: knowing that a file such as `~/.ssh/id_rsa` was opened by a child of an AI coding agent rather than by the user. Without Endpoint Security, macOS offers no supported way to learn which process opened a file; the current polling implementation (FSEvents and lsof) sees that a file changed but not who touched it, and misses short-lived processes entirely. Endpoint Security NOTIFY events provide the audit token and PID for every exec, exit, open and lookup, which is exactly the attribution the detection rules depend on. We use notify events only; we never block or authorize operations. |
| Events used | `ES_EVENT_TYPE_NOTIFY_EXEC`, `ES_EVENT_TYPE_NOTIFY_EXIT`, `ES_EVENT_TYPE_NOTIFY_OPEN`, `ES_EVENT_TYPE_NOTIFY_LOOKUP` |
| Distribution | Outside the Mac App Store, signed with Developer ID and notarized. Installed by the user on their own machines; source code is public. |
| Who installs it | Software developers and security teams monitoring AI coding assistants on their own macOS machines. |
| Contact | the account's email |

Apple answers by email, usually within a few weeks, and may ask follow-up
questions about the use case. The Linux and Windows agents are unaffected
while the request is pending.

## 4. Developer ID Application certificate

This step needs a Mac because the private key must be generated locally and
must never leave it:

1. Keychain Access → Certificate Assistant → **Request a Certificate From a
   Certificate Authority**: your email, common name `Correlic`, "Saved to
   disk". This writes a `.certSigningRequest` and keeps the private key in the
   login keychain.
2. developer.apple.com → Certificates → **+** → **Developer ID Application**
   → upload the request → download the `.cer` → double-click it so Keychain
   Access pairs it with the key.
3. In Keychain Access select the certificate **and** its private key → export
   as `.p12` with a password. This file plus the password become the GitHub
   secrets below.

## 5. After Apple grants the entitlement

1. Identifiers → `com.correlic.agent` → enable the **Endpoint Security**
   capability that is now listed → Save.
2. Profiles → **+** → **Developer ID** (macOS, App) → App ID
   `com.correlic.agent` → the Developer ID Application certificate → name
   `Correlic Agent Developer ID` → Generate → Download. The downloaded
   `.provisionprofile` carries the entitlement; macOS honours the restricted
   entitlement only when this profile is embedded in the app bundle, which is
   why the agent ships as `Correlic Agent.app` rather than a bare binary.

## 6. GitHub secrets

Repository → Settings → Secrets and variables → Actions:

| Secret | Value |
|---|---|
| `APPLE_DEVELOPER_ID_P12` | `base64 -i DeveloperID.p12 \| pbcopy` |
| `APPLE_DEVELOPER_ID_P12_PASSWORD` | the export password |
| `APPLE_PROVISIONING_PROFILE` | `base64 -i "Correlic_Agent_Developer_ID.provisionprofile" \| pbcopy` (after step 5) |
| `APPLE_ID` | the Apple ID email used for notarization |
| `APPLE_TEAM_ID` | the 10-character team id from Membership details |
| `APPLE_APP_PASSWORD` | an app-specific password from <https://account.apple.com> → Sign-In and Security → App-Specific Passwords |

## 7. Build

Run the **Build macOS agent** workflow from the Actions tab with the version
tag, or push a `v*` tag. It builds a universal (arm64 + x86_64) binary with
`-tags esf`, wraps it in `Correlic Agent.app`, signs it with the entitlements
and the embedded profile, notarizes and staples it, and attaches
`correlic-agent-macos-<version>.zip` and `SHA256SUMS-macos.txt` to the draft
release. Without the secrets it still runs and attaches an `-unsigned` zip,
which proves the ESF code builds and can be signed by hand:

```bash
codesign --force --options runtime --timestamp \
  --sign "Developer ID Application: <name> (<team id>)" \
  --entitlements agent/build/correlic-agent.entitlements \
  "Correlic Agent.app"
```

## 8. Install and verify on a Mac

```bash
sudo mkdir -p /etc/correlic /var/log/correlic
sudo cp <agent.yaml written by correlic-admin bootstrap> /etc/correlic/agent.yaml
sudo cp -R "Correlic Agent.app" /Applications/
sudo cp "/Applications/Correlic Agent.app/../com.correlic.agent.plist" /Library/LaunchDaemons/  # from the release zip
sudo chown root:wheel /Library/LaunchDaemons/com.correlic.agent.plist
```

Then System Settings → Privacy & Security → **Full Disk Access** → add
`Correlic Agent.app`. Endpoint Security clients are refused without it
(`ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED`). Start and check:

```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/com.correlic.agent.plist
sudo "/Applications/Correlic Agent.app/Contents/MacOS/correlic-agent" check-compat   # esf: entitlement present
grep -E "Endpoint Security|esf" /var/log/correlic/agent.log | head
```

`Endpoint Security collectors started` means attribution is live. A line
starting with `Endpoint Security unavailable` names the reason and the agent
is running in polling mode.

## Limits and open questions

- Endpoint Security has no network events, so outbound connections still
  come from lsof polling. Per-connection PID attribution on macOS needs a
  Network Extension (content filter), a separate entitlement and extension.
- DNS lookups need a build against the macOS 12 SDK or newer
  (`ES_EVENT_TYPE_NOTIFY_LOOKUP`); the GitHub runners satisfy this.
- Apple's reviewers increasingly expect Endpoint Security clients to be
  packaged as **system extensions** inside a host app. The current design
  runs the ES client in a launchd daemon inside an app bundle, which is the
  smallest change to the existing agent. If Apple asks for a system
  extension, the `esf` package stays as it is and only the host changes.
- Local build on a Mac with Xcode: `cd agent && CGO_ENABLED=1 go build -tags esf -o correlic-agent ./cmd/agent`.
