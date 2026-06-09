# REO

**A local AI security engineer that lives in your terminal, never phones home,
costs less than a coffee subscription, and knows your machine better than any
cloud product ever could.**

REO is privacy-first, terminal-native endpoint security. No website, no
dashboard, no Electron app, no agent phoning home every thirty seconds. You
download one signed binary, type `reo`, and you are inside a secure, local AI
security environment. Everything stays on your machine.

```
   ██████╗ ███████╗ ██████╗
   ██╔══██╗██╔════╝██╔═══██╗
   ██████╔╝█████╗  ██║   ██║
   ██╔══██╗██╔══╝  ██║   ██║
   ██║  ██║███████╗╚██████╔╝
   ╚═╝  ╚═╝╚══════╝ ╚═════╝
   local AI security engineer · never phones home
```

---

## Install

```sh
# macOS / Linux
curl -fsSL https://reo.sh/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://reo.sh/install.ps1 | iex
```

Or grab the signed binary from the landing page and put it on your `PATH`. There
is no GUI installer and no wizard. The terminal is the product.

## Run

```sh
reo                      # drop into the persistent secure REPL
reo scan                 # full system scan with risk scores
reo network              # map active connections, flag public egress
reo shrink photo.png     # shrink a file or a whole folder — free, no account
reo clean                # free disk space by clearing temp files (shows what first)
reo find my resume       # search your folders in plain English
reo plans                # see pricing tiers
reo status               # license, privacy posture, local model
reo upgrade              # buy a plan (the only moment the browser is used)
```

Inside the shell you just talk to it:

```
reo › shrink this screenshot.png
reo › scan my computer
reo › what's running on my network right now
reo › something feels off, investigate
reo › remove the adware
reo › why is my machine slow
reo › scan for my personal info
reo › lock this machine down
reo › I want to go Premium
```

## Privacy is the architecture, not a feature

By default REO is **air-gapped**: it opens no network sockets during operation.
No telemetry, no analytics, no crash reports go anywhere. All inference runs
on-device. The only times the network is touched:

1. `reo upgrade` — opens a Stripe checkout link in your browser to pay.
2. A session you explicitly start with `reo --cloud` for deep cloud-model
   investigations. REO tells you exactly what would be transmitted first.

That's it. Run `reo` and then `privacy` to have it explain this itself.

## The free hook: file shrinking

Anyone can shrink files with REO — no account, no license, no upload. PNGs are
optimized **losslessly in place** (pixels unchanged, still a usable `.png`);
every other format is compressed to a `.gz` sidecar with the original left
untouched. It's the zero-friction reason to install REO; once it's in your
terminal, the security engine is right there too. Like everything else in REO,
it runs entirely on your machine.

```
reo › shrink screenshot.png
✓ screenshot.png  330.4K → 96.2K  (−70.9%, png lossless)
```

## Business model (entirely in the terminal)

Annual plans, validated offline. The license check is **local**: paid tiers are
unlocked by an ed25519-signed token verified on-device — no license server is
called at runtime. Go offline for months and your plan keeps working; the
token's expiry only drives a friendly in-terminal renewal reminder.

| Tier | Per year | Unlocks |
| ---- | -------- | ------- |
| **Free** | C$0 | Real-time scanning, natural-language queries, basic remediation, **file shrinking** |
| **Basic** | C$59.99 | Deep behavioral analysis, 30-day lookback, scheduled scans, one-command full repair |
| **Premium** | C$101.99 | Everything in Basic + local personal-info & secret scan |
| **Advanced** | C$129.99 | Everything in Premium + $1M identity insurance, personal-info removal, financial monitoring (opt-in) |

Run `reo plans` to see this in the terminal. The opt-in Advanced services are the
only features that ever use the network, and only after you explicitly enroll.

---

## Build from source

```sh
cargo build --release    # → target/release/reo  (single ~850 KB static binary)
cargo test               # unit tests for the classifiers + license seal
```

Requires a recent stable Rust toolchain.

## Architecture

```
src/
  main.rs        entry point + arg dispatch
  cli.rs         clap command surface (mirrors the NL intents)
  shell.rs       the persistent secure REPL
  intent.rs      natural-language → action routing
  commands.rs    every action, shared by CLI + REPL
  config.rs      runtime context + local data locations
  license.rs     offline tiered store (Free/Basic/Premium/Advanced) + signed-token activation + pricing
  crypto.rs      ed25519 sign/verify for license tokens (the real seal)
  model.rs       local inference seam (llama.cpp) + heuristic fallback
  shrink.rs      free file + folder shrinking (lossless PNG + universal gzip)
  housekeeping.rs plain-English file find + safe disk cleanup (clean/find/space)
  infra.rs       [Enterprise] conversational cloud infra planning + Terraform generation
  detect.rs      on-device behavioral threat detection (entropy + format masquerade)
  ui.rs          colored TUI output, risk bars, the REO "voice"
  scan/
    types.rs     Finding / Severity / ScanReport + risk scoring
    processes.rs process surface (transient-dir + masquerade heuristics)
    network.rs   socket map + "phoning home" classification
    startup.rs   Run keys + Startup folder persistence
    tasks.rs     scheduled-task abuse patterns
```

## What is real in this build vs. the production roadmap

This repository is a **working vertical slice** on Windows — it really scans your
machine, really gates Pro features, really runs the offline license flow. The
heavier pieces are seamed in cleanly and clearly marked. Nothing is faked
silently.

| Area | This build | Production target |
| ---- | ---------- | ----------------- |
| Process / network / persistence / task scan | ✅ real, via sysinfo + native query tools | ETW (Win) · eBPF (Linux) · ESF (macOS) into the same Finding layer |
| Risk scoring & structured report | ✅ real | unchanged |
| File shrinking (free) | ✅ real — lossless PNG (oxipng) + universal gzip | + lossy image/PDF optimization paths |
| Local personal-info scan (Premium) | ✅ real — flags `.env`, SSH/AWS keys, git creds | broader detectors + entropy-based secret scan |
| Identity services (Advanced) | ⚠️ describes the opt-in enrollment | live insurance/data-broker-removal integrations |
| Local telemetry correlation (`investigate`, `timeline`) | ✅ real, via Windows Event Log | continuous on-device collector (Pro daemon) for true 30-day baselining |
| Natural-language routing | ✅ keyword router (deterministic) | local model classifies, keyword router stays as the fast first pass |
| AI narration | ⚠️ heuristic template engine | bundled llama.cpp + quantized security-fine-tuned 7B/13B GGUF |
| On-device behavioral detection (`detect` / `watch`) | ✅ real — on-demand sweep + real-time `watch` daemon (OS file events) + **process attribution & auto-response** (`watch --respond` names and *kills* the encrypting process via disk-I/O sampling); Shannon-entropy + magic-byte masquerade + ransom notes; fully local, low false-positive | + kernel-ETW per-write attribution (admin), always-on service install, more behavior classes |
| Offline license / Free→Basic→Premium→Advanced gating / renewal | ✅ real flow | same flow; + SQLCipher at rest |
| `upgrade` checkout | ✅ opens your Stripe Payment Link in the browser | + auto-emailed token from a Stripe webhook |
| License integrity seal | ✅ **real ed25519 signature** verified against a public key compiled into the binary | unchanged |
| License issuance / activation | ✅ `reo issue` mints signed tokens (offline private key); `reo activate` verifies them | + webhook automation of issuance |
| Enterprise: conversational cloud infra (`infra` / `infra --apply`) | ✅ real — plan → cost/risk → generated Terraform, **and `--apply` executes it locally via Terraform with YOUR credentials** (DigitalOcean wired; sovereign — keys never leave the machine) | + multi-cloud execution (AWS/Azure/GCP), infrastructure graph, specialized agents |
| `remove` remediation | ✅ plan + confirm + process termination | + file quarantine and registry/persistence surgery (Pro full repair) |
| `lockdown --apply` | ✅ firewall enable (needs elevation) | full service hardening + reversible change log |

The seams to fill are exactly the `model.rs` backend and the kernel-level event
sources behind `scan/`. (License `sign`/`verify` is now real ed25519 in
`crypto.rs`.)

## Local data

Everything REO persists lives under your platform data dir, e.g. on Windows
`%APPDATA%\reo\` (`license.json`, `models/`). To reset to Free, delete
`license.json`. Run `reo status` to see the exact path.
