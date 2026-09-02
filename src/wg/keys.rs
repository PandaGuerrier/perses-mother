//! Génération et encodage des clés WireGuard (Curve25519, base64).
//!
//! WireGuard n'utilise pas de certificats X.509 : chaque pair possède une paire
//! de clés Curve25519 dont la partie publique est échangée hors bande.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use x25519_dalek::{PublicKey, StaticSecret};

use super::error::{Result, WgError};

/// Longueur d'une clé WireGuard brute, en octets.
pub const KEY_LEN: usize = 32;

/// Paire de clés d'un pair WireGuard.
#[derive(Clone)]
pub struct KeyPair {
    private: [u8; KEY_LEN],
    public: [u8; KEY_LEN],
}

impl KeyPair {
    /// Génère une nouvelle paire de clés à partir du CSPRNG du système.
    pub fn generate() -> Self {
        let secret = StaticSecret::random();
        Self::from_secret(secret)
    }

    /// Reconstruit une paire à partir d'une clé privée encodée en base64.
    pub fn from_private_b64(encoded: &str) -> Result<Self> {
        let raw = decode_key(encoded)?;
        Ok(Self::from_secret(StaticSecret::from(raw)))
    }

    fn from_secret(secret: StaticSecret) -> Self {
        let public = PublicKey::from(&secret);
        Self {
            // `wg genkey` stocke la clé déjà "clampée" : on fait de même pour
            // que la clé écrite sur disque soit interchangeable avec la sienne.
            private: clamp(secret.to_bytes()),
            public: public.to_bytes(),
        }
    }

    /// Clé privée encodée en base64, telle qu'attendue par `wg-quick`.
    pub fn private_b64(&self) -> String {
        BASE64.encode(self.private)
    }

    /// Clé publique encodée en base64, à distribuer aux pairs.
    pub fn public_b64(&self) -> String {
        BASE64.encode(self.public)
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &self.public_b64())
            .field("private", &"<redacted>")
            .finish()
    }
}

/// Génère une clé pré-partagée (PSK) de 32 octets, encodée en base64.
pub fn generate_preshared_key() -> String {
    // `StaticSecret::random()` tire 32 octets du CSPRNG ; le clamping ne
    // s'applique pas à une PSK, on repart donc des octets bruts.
    BASE64.encode(StaticSecret::random().to_bytes())
}

/// Valide qu'une chaîne est bien une clé WireGuard base64 de 32 octets.
pub fn validate_key_b64(encoded: &str) -> Result<()> {
    decode_key(encoded).map(|_| ())
}

fn decode_key(encoded: &str) -> Result<[u8; KEY_LEN]> {
    let raw = BASE64
        .decode(encoded.trim())
        .map_err(|e| WgError::InvalidKey(format!("base64 invalide: {e}")))?;
    <[u8; KEY_LEN]>::try_from(raw.as_slice())
        .map_err(|_| WgError::InvalidKey(format!("longueur {} au lieu de {KEY_LEN}", raw.len())))
}

/// Applique le clamping Curve25519 utilisé par `wg genkey`.
fn clamp(mut key: [u8; KEY_LEN]) -> [u8; KEY_LEN] {
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keys_are_valid_base64_32_bytes() {
        let kp = KeyPair::generate();
        validate_key_b64(&kp.private_b64()).unwrap();
        validate_key_b64(&kp.public_b64()).unwrap();
    }

    #[test]
    fn private_key_roundtrips_to_same_public_key() {
        let kp = KeyPair::generate();
        let restored = KeyPair::from_private_b64(&kp.private_b64()).unwrap();
        assert_eq!(kp.public_b64(), restored.public_b64());
    }

    #[test]
    fn private_key_is_clamped_like_wg_genkey() {
        let kp = KeyPair::generate();
        assert_eq!(kp.private[0] & 7, 0);
        assert_eq!(kp.private[31] & 128, 0);
        assert_eq!(kp.private[31] & 64, 64);
    }

    #[test]
    fn rejects_malformed_keys() {
        assert!(validate_key_b64("pas-du-base64!!").is_err());
        assert!(validate_key_b64("dHJvcCBjb3VydA==").is_err());
    }

    #[test]
    fn debug_does_not_leak_private_key() {
        let kp = KeyPair::generate();
        let dbg = format!("{kp:?}");
        assert!(!dbg.contains(&kp.private_b64()));
    }
}
