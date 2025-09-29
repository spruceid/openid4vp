use anyhow::Result;
use async_trait::async_trait;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use ssi::claims::jws::{JwsSigner, JwsSignerInfo};
use ssi::jwk::Algorithm;

pub use ssi::jwk::JWK;

use std::fmt::Debug;

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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

    pub fn from_pkcs8_pem(s: &str) -> Result<Self> {
        let key = p256::SecretKey::from_pkcs8_pem(s)?;
        let jwk = serde_json::from_str(&key.to_jwk_string())?;
        Ok(Self {
            key: key.into(),
            jwk,
        })
    }

    pub fn jwk(&self) -> &JWK {
        &self.jwk
    }
}

#[cfg_attr(target_arch="wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl RequestSigner for P256Signer {
    type Error = anyhow::Error;

    fn alg(&self) -> Result<String, Self::Error> {
        Ok(self.jwk.algorithm.unwrap_or(Algorithm::ES256).to_string())
    }

    fn jwk(&self) -> Result<JWK, Self::Error> {
        Ok(self.jwk.clone())
    }

    async fn sign(&self, payload: &[u8]) -> Vec<u8> {
        let sig: Signature = self.key.sign(payload);
        sig.to_vec()
    }
}

impl JwsSigner for P256Signer {
    async fn fetch_info(&self) -> std::result::Result<JwsSignerInfo, ssi::claims::SignatureError> {
        let algorithm = self.jwk.algorithm.unwrap_or(Algorithm::ES256);

        let key_id = self.jwk.key_id.clone();

        Ok(JwsSignerInfo { algorithm, key_id })
    }

    async fn sign_bytes(
        &self,
        signing_bytes: &[u8],
    ) -> std::result::Result<Vec<u8>, ssi::claims::SignatureError> {
        self.try_sign(signing_bytes)
            .await
            .map_err(|e| ssi::claims::SignatureError::Other(format!("Failed to sign bytes: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use crate::verifier::request_signer::P256Signer;
    use anyhow::Result;

    #[test]
    fn test_p25_from_pkcs8_pem() -> Result<()> {
        let pem = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpuJEtk8m2LIgMcZy
pbrD0ECdHI3UzCnImDfRYydCvFShRANCAARmahl0HOSy+6nH91+Alxe+BF/va3jI
1jSnv8o+7a2nhvU3XKDFLlCR1MBjoJTjy92+H3hPMw3FRFcTamaXA+Co
-----END PRIVATE KEY-----"#;

        let key = P256Signer::from_pkcs8_pem(pem)?;

        println!("JWK: {}", key.jwk());

        Ok(())
    }
}
