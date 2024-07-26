use anyhow::Result;
use async_trait::async_trait;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use ssi::jwk::JWK;

#[async_trait]
pub trait RequestSigner {
    /// The algorithm that will be used to sign.
    fn alg(&self) -> &str;
    /// The public JWK of the signer.
    fn jwk(&self) -> &JWK;
    async fn sign(&self, payload: &[u8]) -> Vec<u8>;
}

#[derive(Debug)]
pub struct P256Signer {
    key: SigningKey,
    jwk: JWK,
}

impl P256Signer {
    pub fn new(key: SigningKey) -> Result<Self> {
        let pk: p256::PublicKey = key.verifying_key().into();
        let jwk = serde_json::from_str(&pk.to_jwk_string())?;
        Ok(Self { key, jwk })
    }
}

#[async_trait]
impl RequestSigner for P256Signer {
    fn alg(&self) -> &str {
        "ES256"
    }

    fn jwk(&self) -> &JWK {
        &self.jwk
    }

    async fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let sig: Signature = self.key.sign(payload);
        sig.to_vec()
    }
}
