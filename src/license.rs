//! Local, offline license store.
//!
//! Paid tiers are unlocked by a **signed token** kept on the machine and
//! verified locally on every run — no license server is contacted. A user can
//! stay offline indefinitely and their tier keeps working; the token's expiry
//! only drives a friendly in-terminal renewal reminder, it is not an
//! enforcement cutoff.
//!
//! Trust comes ONLY from an ed25519 signature (see [`crate::crypto`]) over the
//! token claims, verified against [`REO_PUBLIC_KEY_B64`] which is compiled into
//! the binary. Editing `license.json` by hand cannot grant a tier: the stored
//! `tier` is never trusted, it is re-derived from the verified token each load.

use crate::crypto;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The seller's ed25519 **public** key (base64url). Generate your keypair with
/// `reo keygen`, store the PRIVATE key offline, paste the PUBLIC key here, and
/// rebuild + re-release. Until a real key is set, no token verifies, so paid
/// activation is closed (fail-safe).
pub const REO_PUBLIC_KEY_B64: &str = "W8DmiOaZ3wdiSdHAOa1sFHUwE9TH4FS7lQPk1V9bVRY";

/// Subscription tiers, ordered: Free < Basic < Premium < Advanced < Enterprise.
/// The ordering is what feature gates compare against (`license.has(...)`).
/// Enterprise unlocks REO's cloud "Digital Data Center" mode (infra orchestration).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Tier {
    Free,
    Basic,
    Premium,
    Advanced,
    Enterprise,
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::Free => "Free",
            Tier::Basic => "Basic",
            Tier::Premium => "Premium",
            Tier::Advanced => "Advanced",
            Tier::Enterprise => "Enterprise",
        }
    }
}

/// A purchasable plan. Prices are CAD, annual term (one year), billed yearly.
pub struct Plan {
    pub tier: Tier,
    pub name: &'static str,
    pub tagline: &'static str,
    pub yearly_cad: f64,
    pub features: &'static [&'static str],
}

pub const PLANS: &[Plan] = &[
    Plan {
        tier: Tier::Basic,
        name: "Basic",
        tagline: "Device & local protection",
        yearly_cad: 59.99,
        features: &[
            "Deep behavioral analysis",
            "30-day telemetry lookback",
            "Automated scheduled scans",
            "One-command full system repair",
        ],
    },
    Plan {
        tier: Tier::Premium,
        name: "Premium",
        tagline: "Device, local & personal-info protection",
        yearly_cad: 101.99,
        features: &["Everything in Basic", "Local personal-info & secret scan"],
    },
    Plan {
        tier: Tier::Advanced,
        name: "Advanced",
        tagline: "Maximum protection + priority support",
        yearly_cad: 129.99,
        features: &[
            "Everything in Premium",
            "Priority support",
            "Early access to new protections",
        ],
    },
    Plan {
        tier: Tier::Enterprise,
        name: "Enterprise",
        tagline: "AI Digital Data Center — run cloud infra by chat",
        yearly_cad: 11988.00,
        features: &[
            "Conversational infrastructure: deploy, scale, secure by chat",
            "Multi-cloud planning (AWS/Azure/GCP/DO) with cost & risk estimates",
            "Generated infrastructure-as-code (Terraform) for every change",
            "Cloud security, backup/DR, and cost-optimization planning agents",
        ],
    },
];

pub fn plan(tier: Tier) -> Option<&'static Plan> {
    PLANS.iter().find(|p| p.tier == tier)
}

pub fn plan_by_name(name: &str) -> Option<&'static Plan> {
    let n = name.trim().to_lowercase();
    PLANS.iter().find(|p| p.name.to_lowercase() == n)
}

/// The seller's Stripe Payment Link for a tier. Replace these with the real
/// links from your Stripe dashboard (Payments → Payment Links). Customers pay
/// there and receive a signed token to `reo activate`.
pub fn checkout_url(tier: Tier) -> &'static str {
    match tier {
        Tier::Basic => "https://buy.stripe.com/bJe6oH5EH5TK8oO9Wo8bS00",
        Tier::Premium => "https://buy.stripe.com/fZu28r1or6XO20q4C48bS01",
        Tier::Advanced => "https://buy.stripe.com/cNi4gz0knaa05cC6Kc8bS02",
        Tier::Enterprise => "https://buy.stripe.com/6oUfZh4AD4PG8oOc4w8bS03",
        Tier::Free => "",
    }
}

// ---------------------------------------------------------------------------
// Signed license tokens
// ---------------------------------------------------------------------------

/// The signed claims inside a license token. Format on the wire:
/// `REO1.<base64url(claims_json)>.<base64url(ed25519_sig)>`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Claims {
    pub tier: Tier,
    /// Who it's for — typically the customer email or Stripe customer id.
    pub sub: String,
    /// Issued-at and expiry, unix seconds.
    pub iat: i64,
    pub exp: i64,
}

/// Mint a signed token. Called by the seller's `reo issue` command with the
/// private key from `$REO_SIGNING_KEY`; never used on a customer machine.
pub fn issue_token(private_key_b64: &str, tier: Tier, sub: &str, years: i64) -> crate::Result<String> {
    let now = Utc::now();
    let exp = now + Duration::days(365 * years.max(1));
    let claims = Claims {
        tier,
        sub: sub.to_string(),
        iat: now.timestamp(),
        exp: exp.timestamp(),
    };
    let payload = serde_json::to_vec(&claims)?;
    let sig = crypto::sign(private_key_b64, &payload)?;
    Ok(format!("REO1.{}.{}", B64.encode(&payload), sig))
}

/// Verify a token against the embedded public key. `None` = invalid/forged.
pub fn verify_token(token: &str) -> Option<Claims> {
    verify_token_with(token, REO_PUBLIC_KEY_B64)
}

/// Verify against an arbitrary public key (lets tests exercise the full flow
/// without the real embedded key).
fn verify_token_with(token: &str, public_key_b64: &str) -> Option<Claims> {
    let rest = token.trim().strip_prefix("REO1.")?;
    let (payload_b64, sig_b64) = rest.split_once('.')?;
    let payload = B64.decode(payload_b64).ok()?;
    if !crypto::verify(public_key_b64, &payload, sig_b64) {
        return None;
    }
    serde_json::from_slice::<Claims>(&payload).ok()
}

// ---------------------------------------------------------------------------
// On-disk license
// ---------------------------------------------------------------------------

/// What we persist. The token is the only thing that matters; everything else
/// is re-derived from its verified claims so the file can't be hand-edited into
/// a higher tier.
#[derive(Serialize, Deserialize, Default)]
struct Stored {
    token: Option<String>,
    machine_id: String,
}

#[derive(Clone, Debug, Default)]
pub struct License {
    token: Option<String>,
    pub machine_id: String,
    /// Verified claims, in memory only. `None` ⇒ effectively Free.
    claims: Option<Claims>,
}

impl License {
    fn free() -> Self {
        License {
            token: None,
            machine_id: machine_id(),
            claims: None,
        }
    }

    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join("license.json");
        let Ok(bytes) = std::fs::read(&path) else {
            return License::free();
        };
        let Ok(stored) = serde_json::from_slice::<Stored>(&bytes) else {
            return License::free();
        };
        let machine_id = if stored.machine_id.is_empty() {
            machine_id()
        } else {
            stored.machine_id
        };
        // Trust is the signature, never the stored fields. A token that no
        // longer verifies (forged, or key rotated) falls back to Free.
        let claims = stored.token.as_deref().and_then(verify_token);
        let token = if claims.is_some() { stored.token } else { None };
        License {
            token,
            machine_id,
            claims,
        }
    }

    pub fn save(&self, data_dir: &Path) -> crate::Result<()> {
        let stored = Stored {
            token: self.token.clone(),
            machine_id: self.machine_id.clone(),
        };
        let json = serde_json::to_vec_pretty(&stored)?;
        std::fs::write(data_dir.join("license.json"), json)?;
        Ok(())
    }

    /// The active tier, derived from the verified token (Free if none).
    pub fn tier(&self) -> Tier {
        self.claims.as_ref().map(|c| c.tier).unwrap_or(Tier::Free)
    }

    /// Who the active license is registered to, if any.
    pub fn holder(&self) -> Option<&str> {
        self.claims.as_ref().map(|c| c.sub.as_str())
    }

    /// True when the active (verified) tier is at least `min`.
    pub fn has(&self, min: Tier) -> bool {
        self.tier() >= min
    }

    pub fn is_paid(&self) -> bool {
        self.has(Tier::Basic)
    }

    /// Days until the token expires (renewal reminder), if on a paid plan.
    pub fn days_until_renewal(&self) -> Option<i64> {
        self.claims.as_ref().map(|c| {
            let exp = DateTime::<Utc>::from_timestamp(c.exp, 0).unwrap_or_else(Utc::now);
            (exp - Utc::now()).num_days()
        })
    }

    /// Activate a signed token. Verifies the signature before storing; an
    /// invalid or unsigned token is refused and the license is left unchanged.
    pub fn activate(&mut self, token: &str) -> crate::Result<()> {
        match verify_token(token) {
            Some(claims) => {
                self.token = Some(token.trim().to_string());
                self.claims = Some(claims);
                Ok(())
            }
            None => Err(
                "invalid or unsigned license token — refusing to activate. Check you pasted the \
                 whole token, or contact support."
                    .into(),
            ),
        }
    }
}

/// Derive a stable, local-only machine identifier. Never transmitted; used only
/// for display and optional support reference.
pub fn machine_id() -> String {
    let host = sysinfo::System::host_name().unwrap_or_else(|| "host".into());
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "user".into());
    format!("{:016x}", fnv1a(&format!("{host}:{user}")))
}

/// FNV-1a 64-bit. NOT cryptographic — only a deterministic local fingerprint
/// for the machine id. License integrity is ed25519 (see [`crate::crypto`]).
fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_id_is_stable() {
        assert_eq!(machine_id(), machine_id());
    }

    #[test]
    fn embedded_public_key_is_configured_and_valid() {
        assert!(
            crypto::is_valid_public_key(REO_PUBLIC_KEY_B64),
            "REO_PUBLIC_KEY_B64 must be a valid ed25519 public key (run `reo keygen`)"
        );
    }

    #[test]
    fn tiers_are_ordered() {
        assert!(Tier::Enterprise > Tier::Advanced);
        assert!(Tier::Advanced > Tier::Premium);
        assert!(Tier::Premium > Tier::Basic);
        assert!(Tier::Basic > Tier::Free);
    }

    #[test]
    fn issued_token_carries_the_right_tier() {
        let (priv_b64, pub_b64) = crypto::generate_keypair().unwrap();
        let token = issue_token(&priv_b64, Tier::Premium, "a@b.com", 1).unwrap();
        let claims = verify_token_with(&token, &pub_b64).expect("should verify");
        assert_eq!(claims.tier, Tier::Premium);
        assert_eq!(claims.sub, "a@b.com");
        assert!(claims.exp > claims.iat);
    }

    #[test]
    fn token_signed_by_a_foreign_key_is_rejected() {
        // A token minted with a random key must NOT verify against the embedded
        // public key — this is the anti-forgery guarantee.
        let (priv_b64, _) = crypto::generate_keypair().unwrap();
        let token = issue_token(&priv_b64, Tier::Advanced, "attacker", 99).unwrap();
        assert!(verify_token(&token).is_none());
    }

    #[test]
    fn activate_rejects_garbage_and_stays_free() {
        let mut lic = License::free();
        assert!(lic.activate("REO1.not-a-real-token.nope").is_err());
        assert!(lic.activate("totally bogus").is_err());
        assert!(!lic.is_paid());
        assert_eq!(lic.tier(), Tier::Free);
    }

    #[test]
    fn pricing_is_positive_and_increases_by_tier() {
        let basic = plan(Tier::Basic).unwrap().yearly_cad;
        let premium = plan(Tier::Premium).unwrap().yearly_cad;
        let advanced = plan(Tier::Advanced).unwrap().yearly_cad;
        assert!(basic > 0.0);
        assert!(premium > basic, "premium should cost more than basic");
        assert!(advanced > premium, "advanced should cost more than premium");
    }
}
