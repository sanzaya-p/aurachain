//! Cryptographic primitives: SHA-256 hashing, Ed25519 keys/signatures, addresses.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}

/// Address = "aura" + first 20 bytes of SHA-256(public key), hex encoded.
pub fn address_from_pubkey_bytes(pk: &[u8]) -> String {
    format!("aura{}", hex::encode(&sha256(pk)[..20]))
}

pub fn address_from_pubkey_hex(pk_hex: &str) -> Result<String, String> {
    let pk = hex::decode(pk_hex).map_err(|e| format!("bad pubkey hex: {e}"))?;
    if pk.len() != 32 {
        return Err("pubkey must be 32 bytes".into());
    }
    Ok(address_from_pubkey_bytes(&pk))
}

pub fn is_valid_address(a: &str) -> bool {
    a.len() == 44 && a.starts_with("aura") && a[4..].chars().all(|c| c.is_ascii_hexdigit())
}

pub struct Keypair {
    sk: SigningKey,
}

impl Keypair {
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        Keypair { sk: SigningKey::generate(&mut rng) }
    }

    pub fn from_secret_hex(s: &str) -> Result<Self, String> {
        let b = hex::decode(s.trim()).map_err(|e| format!("bad secret hex: {e}"))?;
        let arr: [u8; 32] = b.try_into().map_err(|_| "secret must be 32 bytes".to_string())?;
        Ok(Keypair { sk: SigningKey::from_bytes(&arr) })
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.sk.to_bytes())
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.sk.verifying_key().to_bytes())
    }

    pub fn address(&self) -> String {
        address_from_pubkey_bytes(&self.sk.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> String {
        hex::encode(self.sk.sign(msg).to_bytes())
    }
}

pub fn verify(pub_hex: &str, msg: &[u8], sig_hex: &str) -> Result<(), String> {
    let pk: [u8; 32] = hex::decode(pub_hex)
        .map_err(|e| format!("bad pubkey hex: {e}"))?
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())?;
    let vk = VerifyingKey::from_bytes(&pk).map_err(|e| format!("invalid pubkey: {e}"))?;
    let sig: [u8; 64] = hex::decode(sig_hex)
        .map_err(|e| format!("bad signature hex: {e}"))?
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    vk.verify(msg, &Signature::from_bytes(&sig))
        .map_err(|_| "signature verification failed".to_string())
}
