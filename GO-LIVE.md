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

### Windows — Azure Trusted Signing (recommended, ~$10/mo, CI-friendly)
1. In the Azure Portal, create a **Trusted Signing** account + certificate
   profile (requires identity verification; individuals are eligible).
2. Add repo secrets: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`,
   `AZURE_TS_ENDPOINT`, `AZURE_TS_ACCOUNT`, `AZURE_TS_PROFILE`.
3. In `.github/workflows/release.yml`, after the Windows "Build" step, add:
   ```yaml
   - name: Sign Windows binary
     if: runner.os == 'Windows'
     uses: azure/trusted-signing-action@v0
     with:
       azure-tenant-id: ${{ secrets.AZURE_TENANT_ID }}
       azure-client-id: ${{ secrets.AZURE_CLIENT_ID }}
       azure-client-secret: ${{ secrets.AZURE_CLIENT_SECRET }}
       endpoint: ${{ secrets.AZURE_TS_ENDPOINT }}
       trusted-signing-account-name: ${{ secrets.AZURE_TS_ACCOUNT }}
       certificate-profile-name: ${{ secrets.AZURE_TS_PROFILE }}
       files-folder: ${{ github.workspace }}
       files-folder-filter: exe
   ```
   (Place it so it signs `reo-x86_64-pc-windows-msvc.exe` *before* the checksum
   step, so the published `.sha256` matches the signed file.)

(Alternative: a traditional Authenticode cert from a CA, ~$200–400/yr.)

### macOS — Apple Developer ID ($99/yr)
1. Join the **Apple Developer Program**, create a **Developer ID Application**
   certificate, export it as a `.p12`.
2. Add secrets for the cert + an app-specific password, then in CI:
   `codesign --deep --options runtime --sign "Developer ID Application: …"` the
   binary, zip it, and `xcrun notarytool submit … --wait` to notarize.

Both slot into `release.yml` as extra steps after "Build release binary".

---

## Phase 4 — Charging money

✅ **The hard part is done.** Licensing is now real ed25519 (`crypto.rs` +
`license.rs`): paid tiers unlock only with a token signed by your private key,
verified against the public key compiled into the binary. Forging a tier is not
possible without your private key. Three steps remain, all yours:

### 1. Generate your signing keypair (once, keep it forever)
```powershell
reo keygen
```
- Put the **PRIVATE** key in a password manager. If you lose it you can't issue
  licenses; if it leaks, anyone can. **Never commit it.**
- Paste the **PUBLIC** key into `REO_PUBLIC_KEY_B64` in `src/license.rs`.
  (Until you do, activation is closed — a safe default.)

### 2. Create Stripe Payment Links
1. Create a **Stripe** account; complete identity + bank verification (KYC).
2. Make a **Product + Payment Link** for each tier (Basic / Premium / Advanced)
   at your prices.
3. Paste each link into `checkout_url()` in `src/license.rs`.

### 3. Deliver tokens after a sale (manual MVP — automate later)
When Stripe emails you that someone paid:
```powershell
$env:REO_SIGNING_KEY = "<your private key>"
reo issue --plan premium --email customer@example.com --years 1
```
Email the printed `REO1.…` token to the customer. They run:
```
reo activate <token>
```
Your private key stays offline (most secure). Later you can automate this with a
Stripe webhook → serverless function that signs + emails the token.

After steps 1–2, commit, tag a new version, and CI re-releases with payments live.

---

## Quick reference: cutting future releases

```powershell
# bump version in Cargo.toml, then:
git tag v0.2.0
git push origin v0.2.0   # CI builds + publishes automatically
```
