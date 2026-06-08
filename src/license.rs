//! Local, offline license store.
//!
//! Paid tiers are unlocked by a signed token kept on the machine and verified
//! locally on every run — no license server is contacted. A user can stay
//! offline indefinitely and their tier keeps working; `renews_at` only drives a
//! friendly in-terminal reminder, it is not an enforcement cutoff.
//!
//! SECURITY NOTE: a shipping build stores this in SQLCipher (encrypted at rest)
//! and verifies an ed25519 signature against a public key baked into the signed
//! binary. This build uses a JSON file and a non-cryptographic checksum as a
//! stand-in so the full flow is exercisable; the `sign`/`verify` seam is where
//! real crypto drops in. It is intentionally NOT a security boundary yet.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Subscription tiers, ordered: Free < Basic < Premium < Advanced. The ordering
/// is what feature gates compare against (`license.has(Tier::Premium)`).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Tier {
    Free,
    Basic,
    Premium,
    Advanced,
}

impl Tier {
    pub fn label(self) -> &'static str {
        match self {
            Tier::Free => "Free",
            Tier::Basic => "Basic",
            Tier::Premium => "Premium",
            Tier::Advanced => "Advanced",
        }
    }
}

/// A purchasable plan. Prices are CAD, annual term (one year), set at 40% below
/// the equivalent McAfee+ tier.
pub struct Plan {
    pub tier: Tier,
    pub name: &'static str,
    pub tagline: &'static str,
    pub monthly_cad: f64,
    pub first_year_cad: f64,
    pub renewal_cad: f64,
    pub features: &'static [&'static str],
}

pub const PLANS: &[Plan] = &[
    Plan {
        tier: Tier::Basic,
        name: "Basic",
        tagline: "Device & local protection",
        monthly_cad: 2.00,
        first_year_cad: 23.99,
        renewal_cad: 59.99,
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
        monthly_cad: 2.50,
        first_year_cad: 29.99,
        renewal_cad: 101.99,
        features: &[
            "Everything in Basic",
            "Local personal-info & secret scan",
        ],
    },
    Plan {
        tier: Tier::Advanced,
        name: "Advanced",
        tagline: "Full protection + identity services",
        monthly_cad: 4.50,
        first_year_cad: 53.99,
        renewal_cad: 129.99,
        features: &[
            "Everything in Premium",
            "$1M identity theft insurance (opt-in)",
            "Personal info removal (opt-in)",
            "Financial-account monitoring (opt-in)",
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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct License {
    pub tier: Tier,
    pub key: Option<String>,
    pub issued_at: Option<DateTime<Utc>>,
    pub renews_at: Option<DateTime<Utc>>,
    pub machine_id: String,
    /// Integrity check over the fields above (placeholder for an ed25519 sig).
    pub seal: String,
}

impl License {
    fn free() -> Self {
        let mut lic = License {
            tier: Tier::Free,
            key: None,
            issued_at: None,
            renews_at: None,
            machine_id: machine_id(),
            seal: String::new(),
        };
        lic.seal = lic.compute_seal();
        lic
    }

    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join("license.json");
        let Ok(bytes) = std::fs::read(&path) else {
            return License::free();
        };
        match serde_json::from_slice::<License>(&bytes) {
            Ok(lic) if lic.seal == lic.compute_seal() => lic,
            // Tampered or corrupt → fail closed to Free.
            _ => License::free(),
        }
    }

    pub fn save(&self, data_dir: &Path) -> crate::Result<()> {
        let path = data_dir.join("license.json");
        let json = serde_json::to_vec_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// True when the active tier is at least `min` AND the seal validates.
    pub fn has(&self, min: Tier) -> bool {
        self.tier >= min && self.seal == self.compute_seal()
    }

    pub fn is_paid(&self) -> bool {
        self.has(Tier::Basic)
    }

    /// Days until the next renewal date, if on a paid plan.
    pub fn days_until_renewal(&self) -> Option<i64> {
        self.renews_at.map(|r| (r - Utc::now()).num_days())
    }

    /// Activate a plan with a one-year term. In production the `key` is the
    /// token returned by the Stripe-backed license service after checkout.
    pub fn activate(&mut self, tier: Tier, key: String) {
        let now = Utc::now();
        self.tier = tier;
        self.key = Some(key);
        self.issued_at = Some(now);
        self.renews_at = Some(now + Duration::days(365));
        self.seal = self.compute_seal();
    }

    /// Push the renewal date out by another annual term.
    pub fn extend(&mut self) {
        let base = self.renews_at.unwrap_or_else(Utc::now).max(Utc::now());
        self.renews_at = Some(base + Duration::days(365));
        self.seal = self.compute_seal();
    }

    fn compute_seal(&self) -> String {
        // Stand-in for an ed25519 signature over the canonical payload.
        let payload = format!(
            "{:?}|{}|{:?}|{:?}|{}",
            self.tier,
            self.key.as_deref().unwrap_or(""),
            self.issued_at,
            self.renews_at,
            self.machine_id
        );
        format!("{:016x}", fnv1a(&payload))
    }
}

/// Derive a stable, local-only machine identifier. Never transmitted; used to
/// bind a license to this install.
pub fn machine_id() -> String {
    let host = sysinfo::System::host_name().unwrap_or_else(|| "host".into());
    let user = std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "user".into());
    format!("{:016x}", fnv1a(&format!("{host}:{user}")))
}

/// FNV-1a 64-bit. NOT cryptographic — a deterministic local fingerprint /
/// integrity checksum only. Replaced by ed25519 verification in a signed build.
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
    fn tiers_are_ordered() {
        assert!(Tier::Advanced > Tier::Premium);
        assert!(Tier::Premium > Tier::Basic);
        assert!(Tier::Basic > Tier::Free);
    }

    #[test]
    fn activation_unlocks_the_right_tiers() {
        let mut lic = License::free();
        assert!(!lic.is_paid());
        lic.activate(Tier::Premium, "REO-PREMIUM-TEST".into());
        assert!(lic.has(Tier::Basic));
        assert!(lic.has(Tier::Premium));
        assert!(!lic.has(Tier::Advanced));
        assert!(lic.days_until_renewal().unwrap() >= 360);
    }

    #[test]
    fn tampering_with_fields_fails_the_seal() {
        let mut lic = License::free();
        lic.activate(Tier::Advanced, "REO-ADVANCED-TEST".into());
        // Forge a different key without re-sealing — must fail closed.
        lic.key = Some("REO-ADVANCED-FORGED".into());
        assert!(!lic.has(Tier::Basic), "tampered license must not validate");
    }

    #[test]
    fn pricing_is_forty_percent_below_mcafee() {
        // McAfee+ first-year CAD: Basic 39.99, Premium 49.99, Advanced 89.99.
        let mcafee = [(Tier::Basic, 39.99), (Tier::Premium, 49.99), (Tier::Advanced, 89.99)];
        for (tier, price) in mcafee {
            let ours = plan(tier).unwrap().first_year_cad;
            let expected = price * 0.6;
            assert!((ours - expected).abs() < 0.5, "{tier:?}: {ours} vs ~{expected}");
        }
    }
}
