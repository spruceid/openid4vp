use anyhow::Result;
use async_trait::async_trait;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use ssi_claims::jws::{JWSSigner, JWSSignerInfo};
use ssi_jwk::Algorithm;

use ssi_jwk::JWK;

use std::fmt::Debug;

#[async_trait]
pub trait RequestSigner: Debug {
    type Error: std::fmt::Display;

    /// The algorithm that will be used to sign.
    fn alg(&self) -> Result<String, Self::Error>;

    /// The public JWK of the signer.
    fn jwk(&self) -> Result<JWK, Self::Error>;

    /// Sign the payload and return the signature.
    async fn sign(&self, payload: &[u8]) -> Vec<u8>;

    /// Attempt to sign the payload and return the signature.
    async fn try_sign(&self, payload: &[u8]) -> Result<Vec<u8>, Self::Error> {
        // default implementation will call sign.
        // Override for custom error handling.
        Ok(self.sign(payload).await)
    }
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

    pub fn jwk(&self) -> &JWK {
        &self.jwk
    }
}

#[async_trait]
impl RequestSigner for P256Signer {
    type Error = anyhow::Error;

    fn alg(&self) -> Result<String, Self::Error> {
        Ok(self
            .jwk
            .algorithm
            .map(|alg| alg)
            .unwrap_or(Algorithm::ES256)
            .to_string())
    }

    fn jwk(&self) -> Result<JWK, Self::Error> {
        Ok(self.jwk.clone())
    }

    async fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let sig: Signature = self.key.sign(payload);
        sig.to_vec()
    }
}

impl JWSSigner for P256Signer {
    async fn fetch_info(&self) -> std::result::Result<JWSSignerInfo, ssi_claims::SignatureError> {
        let algorithm = self.jwk.algorithm.unwrap_or(Algorithm::ES256);

        let key_id = self.jwk.key_id.clone();

        Ok(JWSSignerInfo { algorithm, key_id })
    }

    async fn sign_bytes(
        &self,
        signing_bytes: &[u8],
    ) -> std::result::Result<Vec<u8>, ssi_claims::SignatureError> {
        self.try_sign(signing_bytes).await.map_err(|e| {
            ssi_claims::SignatureError::Other(format!("Failed to sign bytes: {}", e).into())
        })
    }
}
