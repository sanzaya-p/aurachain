//! Hybrid Post-Quantum cryptographic primitives for AuraChain Quantum v1.0:
//!   * Classical elliptic curve: Ed25519 (RFC 8032)
//!   * Post-Quantum lattice:     NIST FIPS 204 ML-DSA-44 (Module-LWE / Module-SIS)
//!   * Hashing & commitments:    NIST FIPS 202 SHA3-256 + FIPS 180-4 SHA-256
//!   * Quantum-shielded address: "aura1q" + first 20 bytes of SHA3-256("aurachain-addr-v1:" || pubkey)
//!
//! Every account is controlled by a single 256-bit (32-byte) master quantum seed,
//! which deterministically expands via domain-separated SHA3-256 into BOTH the
//! Ed25519 signing key and the NIST FIPS 204 ML-DSA-44 lattice signing key.
//! A signature is accepted if and only if BOTH classical and post-quantum
//! signatures verify, defending simultaneously against Shor's quantum algorithm
//! and any future algebraic attack on a single primitive family.

use ed25519_dalek::{Signature as EdSignature, Signer as EdSigner, SigningKey, Verifier as EdVerifier, VerifyingKey};
use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer as PqSigner, Verifier as PqVerifier};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

pub const ED_PK_LEN: usize = 32;
pub const PQ_PK_LEN: usize = ml_dsa_44::PK_LEN; // 1,312 bytes
pub const HYBRID_PK_LEN: usize = ED_PK_LEN + PQ_PK_LEN; // 1,344 bytes

pub const ED_SIG_LEN: usize = 64;
pub const PQ_SIG_LEN: usize = ml_dsa_44::SIG_LEN; // 2,420 bytes
pub const HYBRID_SIG_LEN: usize = ED_SIG_LEN + PQ_SIG_LEN; // 2,484 bytes

pub const ADDR_PREFIX: &str = "aura1q";

#[allow(dead_code)]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[allow(dead_code)]
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}

pub fn sha3_256(bytes: &[u8]) -> [u8; 32] {
    Sha3_256::digest(bytes).into()
}

pub fn sha3_256_hex(bytes: &[u8]) -> String {
    hex::encode(sha3_256(bytes))
}

fn domain_sha3(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(tag);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Quantum-shielded address = "aura1q" + first 20 bytes of SHA3-256("aurachain-addr-v1:" || hybrid_pk).
/// Raw public keys remain hidden behind 256-bit SHA3 preimage security until first spend,
/// and remain protected against Shor's algorithm after spend via ML-DSA-44.
pub fn address_from_pubkey_bytes(pk: &[u8]) -> String {
    let digest = domain_sha3(b"aurachain-addr-v1:", &[pk]);
    format!("{ADDR_PREFIX}{}", hex::encode(&digest[..20]))
}

pub fn address_from_pubkey_hex(pk_hex: &str) -> Result<String, String> {
    let pk = hex::decode(pk_hex).map_err(|e| format!("bad pubkey hex: {e}"))?;
    if pk.len() != HYBRID_PK_LEN {
        return Err(format!("hybrid pubkey must be {HYBRID_PK_LEN} bytes (got {})", pk.len()));
    }
    Ok(address_from_pubkey_bytes(&pk))
}

pub fn is_valid_address(a: &str) -> bool {
    a.len() == ADDR_PREFIX.len() + 40
        && a.starts_with(ADDR_PREFIX)
        && a[ADDR_PREFIX.len()..].chars().all(|c| c.is_ascii_hexdigit())
}

pub struct Keypair {
    seed: [u8; 32],
    ed_sk: SigningKey,
    pq_sk: ml_dsa_44::PrivateKey,
    hybrid_pk: Vec<u8>,
}

impl Clone for Keypair {
    fn clone(&self) -> Self {
        Self::from_seed_bytes(self.seed)
    }
}

impl Keypair {
    pub fn generate() -> Self {
        let seed: [u8; 32] = rand::random();
        Self::from_seed_bytes(seed)
    }

    pub fn from_seed_bytes(seed: [u8; 32]) -> Self {
        let ed_seed = domain_sha3(b"aurachain-ed25519-v1:", &[&seed]);
        let pq_seed = domain_sha3(b"aurachain-mldsa44-v1:", &[&seed]);
        let ed_sk = SigningKey::from_bytes(&ed_seed);
        let (pq_pk, pq_sk) = ml_dsa_44::KG::keygen_from_seed(&pq_seed);
        let mut hybrid_pk = Vec::with_capacity(HYBRID_PK_LEN);
        hybrid_pk.extend_from_slice(&ed_sk.verifying_key().to_bytes());
        hybrid_pk.extend_from_slice(&pq_pk.into_bytes());
        Keypair { seed, ed_sk, pq_sk, hybrid_pk }
    }

    pub fn from_secret_hex(s: &str) -> Result<Self, String> {
        let b = hex::decode(s.trim()).map_err(|e| format!("bad secret seed hex: {e}"))?;
        let arr: [u8; 32] = b.try_into().map_err(|_| "master quantum seed must be 32 bytes (64 hex chars)".to_string())?;
        Ok(Self::from_seed_bytes(arr))
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.seed)
    }

    pub fn public_hex(&self) -> String {
        hex::encode(&self.hybrid_pk)
    }

    #[allow(dead_code)]
    pub fn ed25519_public_hex(&self) -> String {
        hex::encode(&self.hybrid_pk[..ED_PK_LEN])
    }

    #[allow(dead_code)]
    pub fn mldsa44_public_hex(&self) -> String {
        hex::encode(&self.hybrid_pk[ED_PK_LEN..])
    }

    pub fn address(&self) -> String {
        address_from_pubkey_bytes(&self.hybrid_pk)
    }

    /// Produces a deterministic hedged Hybrid Post-Quantum signature:
    ///   sig = Ed25519.Sign(ed_sk, msg) || ML-DSA-44.Sign(pq_sk, msg, ctx="")
    pub fn sign(&self, msg: &[u8]) -> String {
        let ed_sig = self.ed_sk.sign(msg).to_bytes();
        let rnd = domain_sha3(b"aurachain-hedged-v1:", &[&self.seed, msg]);
        let pq_sig = self.pq_sk.try_sign_with_seed(&rnd, msg, b"").expect("ML-DSA-44 signing invariant");
        let mut out = Vec::with_capacity(HYBRID_SIG_LEN);
        out.extend_from_slice(&ed_sig);
        out.extend_from_slice(&pq_sig);
        hex::encode(out)
    }
}

/// Verifies BOTH the classical Ed25519 signature AND the post-quantum NIST FIPS 204 ML-DSA-44 signature.
pub fn verify(pub_hex: &str, msg: &[u8], sig_hex: &str) -> Result<(), String> {
    let pk_bytes = hex::decode(pub_hex).map_err(|e| format!("bad pubkey hex: {e}"))?;
    if pk_bytes.len() != HYBRID_PK_LEN {
        return Err(format!("hybrid pubkey must be {HYBRID_PK_LEN} bytes"));
    }
    let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("bad signature hex: {e}"))?;
    if sig_bytes.len() != HYBRID_SIG_LEN {
        return Err(format!("hybrid signature must be {HYBRID_SIG_LEN} bytes"));
    }

    // 1. Classical Ed25519 verification
    let ed_pk_arr: [u8; ED_PK_LEN] = pk_bytes[..ED_PK_LEN].try_into().unwrap();
    let ed_sig_arr: [u8; ED_SIG_LEN] = sig_bytes[..ED_SIG_LEN].try_into().unwrap();
    let ed_vk = VerifyingKey::from_bytes(&ed_pk_arr).map_err(|e| format!("invalid Ed25519 pubkey: {e}"))?;
    ed_vk
        .verify(msg, &EdSignature::from_bytes(&ed_sig_arr))
        .map_err(|_| "Ed25519 classical signature verification failed".to_string())?;

    // 2. Post-Quantum NIST FIPS 204 ML-DSA-44 verification
    let pq_pk_arr: [u8; PQ_PK_LEN] = pk_bytes[ED_PK_LEN..].try_into().unwrap();
    let pq_sig_arr: [u8; PQ_SIG_LEN] = sig_bytes[ED_SIG_LEN..].try_into().unwrap();
    let pq_vk = ml_dsa_44::PublicKey::try_from_bytes(pq_pk_arr)
        .map_err(|e| format!("invalid ML-DSA-44 post-quantum pubkey: {e}"))?;
    if !pq_vk.verify(msg, &pq_sig_arr, b"") {
        return Err("NIST FIPS 204 ML-DSA-44 post-quantum signature verification failed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_pq_roundtrip_and_js_noble_vector_match() {
        let kp = Keypair::from_seed_bytes([7u8; 32]);
        // Exact cross-language vector generated by @noble/curves + @noble/post-quantum v0.5.4:
        assert_eq!(
            kp.ed25519_public_hex(),
            "18920f5bf21ea859c17cc100dbc99df8c61dad97f9a1e8f40257a6ca0dbca51c"
        );
        assert!(kp
            .mldsa44_public_hex()
            .starts_with("9864fad9f5fda528ed3464644e0a5e046046fd373f445ae52a8d02ec95d15889"));
        assert!(is_valid_address(&kp.address()));

        let msg = b"hello quantum world";
        let sig = kp.sign(msg);
        assert!(verify(&kp.public_hex(), msg, &sig).is_ok());
        assert!(verify(&kp.public_hex(), b"tampered", &sig).is_err());

        // Flip 1 bit inside the ML-DSA-44 lattice portion -> must fail even though Ed25519 still passes!
        let mut raw = hex::decode(&sig).unwrap();
        raw[ED_SIG_LEN + 100] ^= 0x01;
        assert!(verify(&kp.public_hex(), msg, &hex::encode(&raw)).is_err());

        // Flip 1 bit inside the Ed25519 portion -> must fail even though ML-DSA-44 still passes!
        let mut raw2 = hex::decode(&sig).unwrap();
        raw2[10] ^= 0x01;
        assert!(verify(&kp.public_hex(), msg, &hex::encode(&raw2)).is_err());
    }
}
