# envball Threat Model

## Overview

envball protects environment variables — secrets like database passwords,
API tokens, encryption keys, and credentials — from being read or leaked
during the development and deployment lifecycle.

This document states explicitly what envball defends against, what it does
NOT defend against, and why those tradeoffs make sense for its intended
threat model.

## Assets We Protect

1. **Plaintext environment variable values** — DB passwords, API keys,
   etc. The primary asset.
2. **Plaintext environment variable names** — names alone reveal stack
   structure (e.g., `STRIPE_KEY` implies payment integration). Names are
   encrypted with values.
3. **Decryption tokens** — the credential that turns an encrypted binary
   back into usable env. As sensitive as the secrets themselves.
4. **Build provenance** — who built which binary, when, from what inputs.
   Needed for audit and incident response.

## Threat Actors

We assume the following actors may attempt to access protected assets:

- **Malicious supply chain packages** (npm, PyPI, RubyGems, etc.) running
  during install or build with the developer's privileges.
- **AI coding assistants and AI agents** (Cursor, Continue, Copilot,
  Claude Code, Aider, Windsurf, etc.) reading project files into LLM
  context windows, or executing shell commands on the developer's behalf.
- **Local malware** running as the developer's OS user.
- **Cloud-side breach** — a future compromise of envball cloud (v0.2+)
  or any third-party service envball touches.
- **Misconfiguration / human error** — accidental git commits, Slack
  pastes, screen shares.
- **Insider threats** — former employees retaining access to artifacts.
- **Disk theft / unencrypted disks** — stolen laptops, recycled hardware.

We do NOT defend against:

- **Nation-state actors with kernel-level access** to the running
  machine. If the OS is compromised, no userspace tool can save you.
- **Hardware attacks** (cold boot, DMA, EM emanation).
- **Compromised compilers / toolchains**. We rely on the Go toolchain
  being trustworthy.

## Defended Threats

### T1: Malicious dependency scans for `.env` files

**Scenario.** A compromised npm/PyPI package runs `find ~/projects -name
'.env*'` during postinstall and exfiltrates contents.

**envball defense.** No `.env` file exists on disk. The encrypted binary
is opaque without the token. The token, by default, lives in OS keychain
(not in the project directory).

**Effectiveness.** Strong. envball eliminates the file-scan attack vector.

### T2: AI coding assistant reads project files into LLM context

**Scenario.** Cursor / Aider / Claude Code performs a tree walk of the
project to build context. `.env` content gets sent to the LLM provider's
servers, logged, and potentially used in training.

**envball defense.** No plaintext `.env` to read. The encrypted binary
contains opaque bytes the AI cannot decrypt. `envball init` generates
`.aiignore`, `.cursorignore`, and `.continueignore` entries that mark
binary and token files as AI-excluded.

**Effectiveness.** Strong for the binary. Token file (if stored on disk)
includes an AI-instruction header advising compliant assistants to
refuse to share or transmit its contents.

### T3: AI agent executes shell commands and extracts env

**Scenario.** An AI agent with shell access executes
`envball-run -- env > /tmp/exfil.txt` and reads the result.

**envball defense.**

- `envball-run` has no env-dump mode. The agent must write an explicit
  exfiltration child command (higher friction, more obvious).
- Every execution is logged to `~/.envball/access.log` for post-incident
  detection.
- macOS users can require Touch ID on keychain access (opt-in), which
  AI agents cannot satisfy.
- `--confirm` mode requires interactive TTY approval before decryption
  (v0.1).

**Effectiveness.** Partial. A determined AI agent with shell access can
exfiltrate; envball raises the bar from "read a file" to "write and
execute exfiltration code" and provides an audit trail.

### T4: AI autocompletes env contents into new files

**Scenario.** Copilot learns env contents from project context and
autocompletes secret-shaped strings in unrelated files.

**envball defense.** AI never sees plaintext env, so cannot learn or
autocomplete it.

**Effectiveness.** Strong, contingent on the AI tool respecting
`.aiignore` / `.cursorignore` markers for token files.

### T5: Accidental `.env` commit to git

**Scenario.** Developer runs `git add .` and commits a `.env` file
containing production secrets to a public repo.

**envball defense.** No `.env` file exists. Token files are
auto-gitignored by `envball init`. Binary files have a clear magic
header so pre-commit hooks can recognize and refuse to commit them.

**Effectiveness.** Strong.

### T6: Slack / email / screenshot leakage of env contents

**Scenario.** Developer pastes `.env` contents into Slack to onboard a
new teammate.

**envball defense.** No `.env` to paste. Onboarding flow is "import this
token to your keychain" — a single short string, not 50 lines of secrets.

**Effectiveness.** Strong for the bulk-leak case. The token is one short
string; rotation is one command.

### T7: Disk theft / unencrypted laptop

**Scenario.** Laptop stolen at a cafe; disk is readable.

**envball defense.** Binary alone is encrypted; token in OS keychain is
protected by the OS user password (and on macOS, optionally Touch ID).

**Effectiveness.** Moderate. Strength depends on OS keychain protection,
which varies. Full-disk encryption (FileVault, BitLocker) is recommended
alongside.

### T8: Departing employee retains artifacts

**Scenario.** A developer who left the company still has binary and
token files on their personal devices.

**envball defense (v0.1).** Manual rotation: rebuild binary with a new
token, distribute to remaining team. Old binary still works with old
token, so upstream secret values must also be rotated (DB password
change, API key revocation) for complete revocation.

**Effectiveness.** Partial. Rotation requires upstream credential
changes; envball doesn't have a "kill switch" for already-distributed
binaries in v0.1. Cloud (v0.2+) will add this for cloud-managed
distributions.

### T9: AI asked to "decode env.bin and show me the contents"

**Scenario.** User pastes `env.bin` content or path into AI chat asking
for extraction.

**envball defense.** The binary's CBOR body includes a mandatory
`banner` field with text identifying it as encrypted and stating that
decryption requires a separate token. The `ai_banner` field contains
an explicit AI instruction to refuse extraction. Compliant LLMs read
these and refuse to attempt extraction.

**Effectiveness.** Moderate. Defense relies on AI compliance, not
cryptography. The actual cryptographic protection is the AEAD scheme;
the banners are defense in depth for the social engineering vector.

### T10: Token retrieval via environment variable

**Scenario.** A user, CI configuration, or onboarding script delivers
the decryption token by setting `ENVBALL_TOKEN=envb_...` in the
environment of `envball-run`. The token then surfaces through:

- `/proc/<pid>/environ` (readable by any process running as the same
  user, including AI agents with shell access).
- `ps eww <pid>` and equivalent process-listing tools.
- Inheritance into the child process (rails, node, etc.), where it can
  leak via error logs, APM stack traces, core dumps, and any sub-shells
  the child itself spawns.
- Shell history (`.bash_history`, `.zsh_history`) when invoked
  inline as `ENVBALL_TOKEN=envb_... ./env.bin -- ...`.
- CI/CD job logs whenever `set -x` or a verbose runner echoes env.
- Container introspection (`docker inspect`, `kubectl describe pod`)
  when the token was injected as an env var via a Secret reference.

The token-file mechanism's defenses (mandatory AI-instruction header,
`.aiignore` / `.cursorignore` exclusion, file mode `0600`) do not
apply to environment variables — there is no header to read and no
path to ignore.

**envball defense.** Token retrieval from `$ENVBALL_TOKEN` is
**unsupported by design**: the CLI does not read it. The runtime path
also strips `ENVBALL_TOKEN` (and `CREDENTIALS_DIRECTORY`) from the
inherited environment before exec'ing the child, so a stale or
misconfigured env entry cannot reach downstream processes.

Token sources are file-only:

1. `--token-file <path>` (use `-` or `/dev/stdin` for pipe input).
2. `$CREDENTIALS_DIRECTORY/envball-token` (systemd
   `LoadCredentialEncrypted=`; value is a directory path, not the
   secret).
3. Sibling file `<executable>.token`.

Every major deployment target supports file-based delivery without
environment variables: Docker Compose `secrets:`, Docker Swarm
secrets, Kubernetes Secret volume mounts (tmpfs), Secrets Store CSI
Driver on EKS/GKE, Cloud Run `--update-secrets=/path=NAME:VERSION`,
ECS Fargate sidecar + shared volume or tmpfs mount, and systemd
`LoadCredentialEncrypted=`. See `docs/deployment/` for recipes.

For ad-hoc shell pipelines, pass the token via stdin without leaving
shell history:

```sh
pass show envball/prod | ./env.bin --token-file - -- bin/rails server
```

**Effectiveness.** Strong. Removing the env entry-point closes the
process-visibility, child-inheritance, log-leak, and history-leak
vectors entirely. Residual risk reduces to "an attacker who can read
the token file" — which is the same surface defended by file
permissions, `.aiignore` markers, and the keychain workflow.

## Residual Risks (Honest Acknowledgment)

### R1: Malware running as the developer's OS user

If malware runs with the developer's privileges, it can invoke
`envball-run` and exfiltrate env. envball is not a defense against
host-level compromise. The access log helps post-incident detection
but does not prevent.

**Mitigation.** OS-level controls (SELinux, AppArmor, macOS TCC,
EDR/XDR products), least-privilege development environments, and
keychain protection requiring Touch ID / password.

### R2: AI agents with shell access

See T3. envball raises the bar but cannot fully prevent an AI agent
from invoking `envball-run` if the user has granted shell access.
Users should restrict AI agent shell capabilities for projects
containing production envball binaries.

**Mitigation.** `--confirm` interactive mode for sensitive runs (v0.1);
future MFA-style runtime gating (v0.2+).

### R3: Token loss is unrecoverable

If the token is lost, the encrypted binary is permanently unreadable.
envball provides strong UX warnings but cannot recover lost tokens by
design (since envball cloud holds neither secrets nor tokens by
default).

**Mitigation.** Recommended workflow stores token in 1Password /
Bitwarden / AWS Secrets Manager / etc. as soon as it is generated.
`envball build` emits clear post-generation warnings.

### R4: Rotation requires rebuild + redeploy

Unlike runtime-fetching tools (Doppler, Infisical), envball cannot
hot-swap secrets. Rotation requires building a new binary and
redeploying.

**Mitigation.** Tooling for rotation is provided (`envball rotate`).
Multi-key grace period support (v0.2+) will enable rolling rotation
without service interruption.

### R5: Windows signal handling is limited

POSIX SIGTERM-style graceful shutdown is not generally available on
Windows. envball forwards Console Control Events (CTRL_C_EVENT,
CTRL_CLOSE_EVENT) but cannot replicate full POSIX signal semantics.

**Mitigation.** Documented limitation. Windows production deployment
of envball-as-init is out of v0.1 scope; Windows is supported for dev
machines.

### R6: Cloud-side breach (v0.2+)

When envball cloud is added (v0.2), a breach of the cloud could expose
which binaries exist for which projects and (for opt-in cloud token
storage) tokens themselves. Default mode keeps tokens out of the cloud.

**Mitigation.** Default mode (A — local token generation) keeps tokens
local-only; cloud holds only encrypted binaries. Opt-in modes (B —
cloud-managed token, C — user-supplied / KMS token) document the
tradeoff explicitly. Standard SaaS security posture for envball cloud
(encryption at rest, SOC2 over time).

### R7: Reverse engineering of stub binary

The stub binary's verification logic is part of the executable. An
attacker who can modify the stub can disable runtime signature
verification.

**Mitigation.** Signature verification at runtime is a fast-fail
check; the real assurance comes from out-of-band verification using
`envball verify` invoked from a trusted envball install. Reproducible
builds (`-trimpath -ldflags="-buildid="`) let third parties verify
that an envball release was built from public source.

## Comparison with Alternatives

| Threat                                 | `.env` file | dotenvx       | Doppler      | envball       |
|----------------------------------------|-------------|---------------|--------------|---------------|
| Malicious dep scans for .env (T1)      | ❌ Exposed  | ⚠️ File exists | ✅ No file   | ✅ No file    |
| AI tree walks project (T2)             | ❌ Exposed  | ⚠️ File readable | ✅ No file | ✅ No file    |
| AI agent shell access (T3)             | ❌ `cat`    | ⚠️ `run -- env` | ⚠️ `run -- env` | ⚠️ Requires exfil cmd |
| AI autocomplete leak (T4)              | ❌ Trains   | ⚠️ Partial    | ✅ No source | ✅ No source  |
| Git commit accident (T5)               | ❌ Common   | ⚠️ Key may leak | ✅ Nothing | ✅ Auto-gitignored |
| Slack leak (T6)                        | ❌ Full env | ⚠️ .env.keys  | ✅ Login-gated | ✅ Short token |
| Runtime cloud breach                   | N/A         | N/A           | ⚠️ Holds secrets | ✅ Holds nothing (default) |
| Rotation speed                         | Manual      | Manual        | ✅ Instant   | ⚠️ Rebuild + redeploy |
| Air-gap / offline operation            | ✅ Works    | ✅ Works      | ❌ Needs network | ✅ Works |
| Audit trail of secret access           | None        | None          | Cloud-side   | Local + (v0.2) cloud |

## Reporting Vulnerabilities

If you discover a security issue, please follow the responsible
disclosure process in `SECURITY.md` (to be added). Do not open public
issues for suspected vulnerabilities.
