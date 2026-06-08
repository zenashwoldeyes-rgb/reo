// REO license webhook — Cloudflare Worker.
//
// Flow it automates (steps 2–4 of selling REO):
//   Stripe "payment succeeded"  →  mint a signed license token  →  email it.
// The customer then runs `reo activate <token>`. Your ed25519 private key lives
// only in this Worker's secrets; it is never in the binary or the repo.
//
// Zero npm dependencies: Stripe signature check (HMAC) and token signing
// (ed25519) both use Web Crypto.

import { issueToken } from "./sign.mjs";

// Map the Stripe price (pre-tax, in cents CAD) to a REO tier. These must match
// your Payment Link prices. If you change a price in Stripe, update it here too.
const TIER_BY_AMOUNT = {
  5999: "Basic",
  10199: "Premium",
  12999: "Advanced",
};

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response("REO license webhook is running.", { status: 200 });
    }

    const body = await request.text();
    const sig = request.headers.get("stripe-signature") || "";
    if (!(await verifyStripeSignature(body, sig, env.STRIPE_WEBHOOK_SECRET))) {
      return new Response("invalid signature", { status: 400 });
    }

    let event;
    try {
      event = JSON.parse(body);
    } catch {
      return new Response("bad json", { status: 400 });
    }

    const sale = extractSale(event);
    if (!sale) {
      // Not a sale we act on (e.g. other event types) — ack so Stripe stops.
      return new Response("ignored", { status: 200 });
    }

    const tier = sale.metadataTier || TIER_BY_AMOUNT[sale.amount];
    if (!sale.email || !tier) {
      // Paid but we couldn't map it — log loudly; ack to avoid endless retries.
      console.error("UNMAPPED SALE", { email: sale.email, amount: sale.amount });
      return new Response("ok (unmapped — check TIER_BY_AMOUNT)", { status: 200 });
    }

    const token = await issueToken(env.REO_SIGNING_KEY, tier, sale.email, 1);
    await sendLicenseEmail(env, sale.email, tier, token);
    console.log("ISSUED", { email: sale.email, tier });
    return new Response("issued", { status: 200 });
  },
};

// Pull (email, amount, tier) out of the events that represent money received:
//  - checkout.session.completed  → first purchase (one-time or new subscription)
//  - invoice.payment_succeeded   → subscription renewals only (avoid double-issue)
function extractSale(event) {
  const o = event.data?.object;
  if (event.type === "checkout.session.completed") {
    return {
      email: o.customer_details?.email || o.customer_email,
      amount: o.amount_subtotal,
      metadataTier: o.metadata?.tier,
    };
  }
  if (event.type === "invoice.payment_succeeded" && o.billing_reason === "subscription_cycle") {
    return { email: o.customer_email, amount: o.subtotal, metadataTier: undefined };
  }
  return null;
}

// Verify Stripe's webhook signature (HMAC-SHA256) with a 5-minute tolerance.
async function verifyStripeSignature(payload, header, secret) {
  if (!secret || !header) return false;
  let t = null;
  const v1s = [];
  for (const part of header.split(",")) {
    const [k, v] = part.split("=");
    if (k === "t") t = v;
    if (k === "v1") v1s.push(v);
  }
  if (!t || v1s.length === 0) return false;
  if (Math.abs(Math.floor(Date.now() / 1000) - Number(t)) > 300) return false;

  const expected = await hmacHex(secret, `${t}.${payload}`);
  return v1s.some((v) => timingSafeEqual(v, expected));
}

async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg)));
  return [...sig].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function sendLicenseEmail(env, to, tier, token) {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: env.FROM_EMAIL,
      to,
      subject: `Your REO ${tier} license`,
      text:
        `Thanks for buying REO ${tier}!\n\n` +
        `Activate it by opening your terminal and running:\n\n` +
        `  reo activate ${token}\n\n` +
        `Keep this token somewhere safe — it's your license. Enjoy REO.\n`,
    }),
  });
  if (!res.ok) {
    // Throw so Stripe retries and the customer still gets their token.
    throw new Error(`email send failed: ${res.status} ${await res.text()}`);
  }
}
