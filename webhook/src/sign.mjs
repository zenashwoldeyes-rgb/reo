// REO license-token signing — runtime-agnostic (Cloudflare Workers, Node 18+).
//
// Produces the EXACT token format REO's Rust binary verifies:
//   REO1.<base64url(claims_json)>.<base64url(ed25519_sig)>
// where claims_json = {"tier":"Premium","sub":"<email>","iat":<sec>,"exp":<sec>}
// and the signature is ed25519 over the claims_json bytes.
//
// Uses only Web Crypto (crypto.subtle), so there are no npm dependencies.

function b64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Fixed DER prefix that wraps a raw 32-byte ed25519 seed as PKCS#8, which is
// what crypto.subtle.importKey expects for an Ed25519 private key.
const PKCS8_ED25519_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
  0x22, 0x04, 0x20,
]);

async function importSigningKey(privateKeyB64) {
  const seed = b64urlDecode(privateKeyB64.trim());
  if (seed.length !== 32) throw new Error("REO_SIGNING_KEY must be a 32-byte base64url key");
  const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32);
  pkcs8.set(PKCS8_ED25519_PREFIX, 0);
  pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
  return crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
}

// Mint a signed license token. `tier` must be exactly "Basic", "Premium", or
// "Advanced" (matching REO's Tier enum). `years` defaults to 1.
export async function issueToken(privateKeyB64, tier, sub, years = 1) {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + Math.max(1, years) * 365 * 86400;
  // Field order (tier, sub, iat, exp) is irrelevant to verification — REO
  // verifies the signature over these exact bytes, then JSON-parses them.
  const payload = new TextEncoder().encode(JSON.stringify({ tier, sub, iat, exp }));
  const key = await importSigningKey(privateKeyB64);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, payload));
  return `REO1.${b64url(payload)}.${b64url(sig)}`;
}
