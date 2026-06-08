# Taking REO live (desktop)

A practical, ordered checklist. Phase 1 gets you **installable by anyone, today,
for free**. Later phases are polish and revenue. Nothing here is faked.

---

## Phase 1 — Live on GitHub (free, do this first)

This makes `reo` installable on Windows/macOS/Linux with a single command. No
domain, no money, no servers.

1. **Create the public repo and push** (run from this folder):
   ```powershell
   git add -A
   git commit -m "Initial REO release pipeline"
   gh repo create reo --public --source . --remote origin --push
   ```
   This uses your logged-in GitHub account (`zenashwoldeyes-rgb`). If you pick a
   different repo name, update the three files that reference
   `zenashwoldeyes-rgb/reo`: `install/install.sh`, `install/install.ps1`,
   `landing/index.html` (and `landing/_redirects` for Phase 2).

2. **Cut your first release.** Tagging triggers `.github/workflows/release.yml`,
   which builds all 5 platform binaries and publishes them as a GitHub Release:
   ```powershell
   git tag v0.1.0
   git push origin v0.1.0
   ```
   Watch it build under the **Actions** tab (~5–10 min). When it's done, the
   **Releases** page will have `reo-<platform>` binaries + `.sha256` files +
   `install.sh` / `install.ps1`.

3. **Test the real install** on a clean machine (or VM):
   ```sh
   # macOS / Linux
   curl -fsSL https://github.com/zenashwoldeyes-rgb/reo/releases/latest/download/install.sh | sh
   ```
   ```powershell
   # Windows
   irm https://github.com/zenashwoldeyes-rgb/reo/releases/latest/download/install.ps1 | iex
   ```

✅ At this point REO is genuinely live and anyone can install it.

---

## Phase 2 — The `reo.sh` vanity domain (optional, ~$10–40/yr)

Purely cosmetic — makes `curl reo.sh/install.sh | sh` and pretty download links
work. Skip until Phase 1 is proven.

1. Buy `reo.sh` (Cloudflare Registrar, Namecheap, etc.).
2. Create a **Cloudflare Pages** project, connect this GitHub repo, set the build
   output directory to `landing`, no build command.
3. Add `reo.sh` as a custom domain on the Pages project.
4. `landing/_redirects` (already in this repo) forwards `reo.sh/install.sh` and
   `reo.sh/dl/...` to GitHub, so GitHub Releases stays the source of truth.
5. Switch the hero command on the landing page and in `README.md` back to the
   branded `curl reo.sh/install.sh | sh`.

---

## Phase 3 — Code signing (the real trust gate, costs money)

Without this, Windows SmartScreen and macOS Gatekeeper show scary "unknown
developer" warnings. The binaries still run, but most users bail. Do this before
any real marketing push.

- **Windows:** Authenticode certificate (~$200–400/yr from a CA), or
  **Azure Trusted Signing** (~$10/mo) — cheaper and CI-friendly. Sign
  `reo.exe` in the workflow before upload.
- **macOS:** Apple Developer Program ($99/yr) → Developer ID cert → `codesign`
  the binary, then `notarytool` to notarize. Otherwise Gatekeeper blocks it.

Both slot into `release.yml` as extra steps after "Build release binary".

---

## Phase 4 — Charging money (do the crypto first)

⚠️ **Before you take a single payment**, fix the license seal. `README.md` and
`license.rs` both flag that the current integrity check is an FNV checksum —
**not** a security boundary. Anyone could unlock paid tiers for free. Replace it
with the ed25519 signing the README describes (sign tokens server-side, verify
against a public key baked into the binary).

Then:
1. Create a **Stripe** account + a Checkout for each paid tier.
2. Point `reo upgrade` at the live Checkout link.
3. Issue the signed license token from a Stripe webhook after payment.

This is the one piece I flagged separately — say the word and I'll implement the
ed25519 sign/verify next.

---

## Quick reference: cutting future releases

```powershell
# bump version in Cargo.toml, then:
git tag v0.2.0
git push origin v0.2.0   # CI builds + publishes automatically
```
