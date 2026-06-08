# REO license webhook

Automates issuing + emailing license tokens after a Stripe payment, so you don't
run `reo issue` by hand for every sale. It's a single Cloudflare Worker with no
npm dependencies.

```
Stripe (payment) ──webhook──▶ this Worker ──▶ signs ed25519 token ──▶ emails customer
                                                                         │
                                              customer runs: reo activate <token>
```

Your ed25519 **private key lives only in the Worker's secrets** — never in the
binary, never in the repo.

## What you need (one-time accounts)
1. **Cloudflare** account (free) — hosts the Worker.
2. **Resend** account (free tier) — sends the license email. Verify a sending
   domain, or use `onboarding@resend.dev` for testing (only emails *you*).
3. Your **Stripe** account (already set up).

## Deploy (about 10 minutes)

From this `webhook/` folder:

```powershell
npm install -g wrangler   # or use: npx wrangler ...
wrangler login            # opens the browser to authorize Cloudflare
wrangler deploy           # prints your Worker URL, e.g. https://reo-license-webhook.<you>.workers.dev
```

Copy that Worker URL — you'll give it to Stripe next.

### Set the three secrets
```powershell
wrangler secret put REO_SIGNING_KEY        # paste your ed25519 PRIVATE key (from `reo keygen`)
wrangler secret put RESEND_API_KEY         # paste your Resend API key
wrangler secret put STRIPE_WEBHOOK_SECRET  # paste the value from the next step
```

Also edit `FROM_EMAIL` in `wrangler.toml` to a verified Resend sender, then
`wrangler deploy` again.

### Point Stripe at the Worker
1. Stripe Dashboard → **Developers → Webhooks → Add endpoint**.
2. Endpoint URL = your Worker URL.
3. Select events: **`checkout.session.completed`** and
   **`invoice.payment_succeeded`** (the second one auto-handles renewals).
4. After creating it, reveal the **Signing secret** (`whsec_…`) and put it in
   `STRIPE_WEBHOOK_SECRET` (the command above).

## Test it
- In the Stripe webhook page, click **Send test webhook → `checkout.session.completed`**.
  (Test events may not map to a tier/email — a real test purchase is the true check.)
- Best test: make a real purchase in Stripe **test mode**, then confirm the
  email arrives and `reo activate <token>` unlocks the tier.

## Keeping prices in sync
Tier is matched by the pre-tax amount in `src/index.mjs` (`TIER_BY_AMOUNT`):
`5999 → Basic, 10199 → Premium, 12999 → Advanced` (cents, CAD). **If you change a
price in Stripe, update this map and redeploy.** (Optional: set `metadata.tier`
on each Payment Link to map by metadata instead of amount.)

## Notes
- The token-signing code (`src/sign.mjs`) is byte-compatible with the Rust
  verifier — cross-checked: a JS-signed token activates in `reo`.
- If the email send fails, the Worker returns an error so Stripe retries; the
  customer still gets their token.
