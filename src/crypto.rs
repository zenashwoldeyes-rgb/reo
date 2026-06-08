//! ed25519 primitives for license tokens.
//!
//! This is the real security boundary that replaces the old FNV checksum. The
//! private (signing) key never ships in the binary — only the public
//! (verifying) key is baked in (see `license::REO_PUBLIC_KEY_B64`). Tokens are
//! minted offline by the seller with `reo issue` (which reads the private key
//! from `$REO_SIGNING_KEY`) and verified on every machine against the embedded
//! public key. Forging a paid tier therefore requires the private key, which
//! only the seller holds.

use crate::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Generate a fresh ed25519 keypair. Returns (private_b64, public_b64), both
/// base64url (no padding). The private string is the secret — store it offline.
pub fn generate_keypair() -> Result<(String, String)> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("OS RNG failed: {e}"))?;
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    Ok((B64.encode(sk.to_bytes()), B64.encode(vk.to_bytes())))
}

/// True if `b64` decodes to a well-formed 32-byte ed25519 public key. Used to
/// guard the embedded `REO_PUBLIC_KEY_B64` against typos/truncation.
pub fn is_valid_public_key(b64: &str) -> bool {
    let Ok(bytes) = B64.decode(b64.trim()) else {
        return false;
    };
    let Ok(arr): std::result::Result<[u8; 32], _> = bytes.as_slice().try_into() else {
        return false;
    };
    VerifyingKey::from_bytes(&arr).is_ok()
}

/// Sign `msg` with a base64url private key, returning a base64url signature.
pub fn sign(private_key_b64: &str, msg: &[u8]) -> Result<String> {
    let bytes = B64
        .decode(private_key_b64.trim())
        .map_err(|_| "signing key is not valid base64url")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signing key must be 32 bytes")?;
    let sk = SigningKey::from_bytes(&arr);
    let sig = sk.sign(msg);
    Ok(B64.encode(sig.to_bytes()))
}

/// Verify `msg` against a base64url signature using a base64url public key.
/// Returns false on any decode/parse/verify failure — never panics.
pub fn verify(public_key_b64: &str, msg: &[u8], sig_b64: &str) -> bool {
    let Ok(pk_bytes) = B64.decode(public_key_b64.trim()) else {
        return false;
    };
    let Ok(pk_arr): std::result::Result<[u8; 32], _> = pk_bytes.as_slice().try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let Ok(sig_bytes) = B64.decode(sig_b64) else {
        return false;
    };
    let Ok(sig_arr): std::result::Result<[u8; 64], _> = sig_bytes.as_slice().try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify_strict(msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_then_verify_roundtrips() {
        let (priv_b64, pub_b64) = generate_keypair().unwrap();
        let msg = b"tier=premium;sub=customer@example.com";
        let sig = sign(&priv_b64, msg).unwrap();
        assert!(verify(&pub_b64, msg, &sig));
    }

    #[test]
    fn tampered_message_fails() {
        let (priv_b64, pub_b64) = generate_keypair().unwrap();
        let sig = sign(&priv_b64, b"tier=basic").unwrap();
        assert!(!verify(&pub_b64, b"tier=advanced", &sig));
    }

    #[test]
    fn wrong_key_fails() {
        let (priv_b64, _) = generate_keypair().unwrap();
        let (_, other_pub) = generate_keypair().unwrap();
        let sig = sign(&priv_b64, b"tier=premium").unwrap();
        assert!(!verify(&other_pub, b"tier=premium", &sig));
    }
}
