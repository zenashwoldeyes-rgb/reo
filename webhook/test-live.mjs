// Fire a simulated Stripe "checkout.session.completed" at your LIVE Worker to
// prove the whole pipeline (signature check → token mint → email) end-to-end,
// without a real purchase. Your secrets stay on your machine.
//
// Prereq: you've set REO_SIGNING_KEY, RESEND_API_KEY, and STRIPE_WEBHOOK_SECRET
// on the Worker (`wrangler secret put ...`). Use the SAME STRIPE_WEBHOOK_SECRET
// value here. (For a pure pipeline test you can pick any string as that secret,
// as long as it matches on the Worker and here.)
//
// Usage (PowerShell, from the webhook/ folder):
//   $env:WORKER_URL = "https://reo-license-webhook.reo-security.workers.dev"
//   $env:STRIPE_WEBHOOK_SECRET = "<same value you set on the Worker>"
//   node test-live.mjs you@example.com premium

const url = process.env.WORKER_URL;
const secret = process.env.STRIPE_WEBHOOK_SECRET;
const email = process.argv[2];
const tier = (process.argv[3] || "premium").toLowerCase();

const AMOUNTS = { basic: 5999, premium: 10199, advanced: 12999 };
if (!url || !secret || !email || !AMOUNTS[tier]) {
  console.error(
    "Set WORKER_URL and STRIPE_WEBHOOK_SECRET env vars, then run:\n" +
      "  node test-live.mjs <email> <basic|premium|advanced>"
  );
  process.exit(1);
}

const body = JSON.stringify({
  type: "checkout.session.completed",
  data: { object: { customer_details: { email }, amount_subtotal: AMOUNTS[tier] } },
});

const t = Math.floor(Date.now() / 1000);
const key = await crypto.subtle.importKey(
  "raw",
  new TextEncoder().encode(secret),
  { name: "HMAC", hash: "SHA-256" },
  false,
  ["sign"]
);
const sigBytes = new Uint8Array(
  await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${t}.${body}`))
);
const hex = [...sigBytes].map((b) => b.toString(16).padStart(2, "0")).join("");

const res = await fetch(url, {
  method: "POST",
  headers: { "stripe-signature": `t=${t},v1=${hex}`, "content-type": "application/json" },
  body,
});
const text = await res.text();
console.log(`Worker response: ${res.status} ${text}`);
if (res.status === 200 && text.includes("issued")) {
  console.log(`✅ Pipeline works. Check ${email} for the license email, then: reo activate <token>`);
} else {
  console.log("⚠️  Not issued. Check the Worker logs in another terminal with:  wrangler tail");
}
