use anyhow::Result;
use anyhow::{bail, Error};
use p256::ecdsa::signature::Verifier as _;
use rsa::pkcs1v15::{Signature as RsaSignature, VerifyingKey as RsaVerifyingKey};
use rsa::RsaPublicKey;
use sha2::{Sha256, Sha384, Sha512};
use x509_cert::spki::SubjectPublicKeyInfoRef;

pub trait Verifier: Sized {
    /// Construct a [Verifier] from [SubjectPublicKeyInfoRef].
    ///
    /// ## Params
    /// * `spki` - the public key information necessary to construct a [Verifier].
    /// * `algorithm` - the value taken from the `alg` header of the request, to hint at what curve should be used by the [Verifier].
    fn from_spki(spki: SubjectPublicKeyInfoRef<'_>, algorithm: String) -> Result<Self>;
    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct P256Verifier(p256::ecdsa::VerifyingKey);

impl Verifier for P256Verifier {
    fn from_spki(spki: SubjectPublicKeyInfoRef<'_>, algorithm: String) -> Result<Self> {
        if algorithm != "ES256" {
            bail!("P256Verifier cannot verify requests signed with '{algorithm}'")
        }
        spki.try_into().map(Self).map_err(Error::from)
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        let signature = p256::ecdsa::Signature::from_slice(signature)?;
        self.0.verify(payload, &signature).map_err(Error::from)
    }
}

#[derive(Debug, Clone)]
pub struct P384Verifier(p384::ecdsa::VerifyingKey);

impl Verifier for P384Verifier {
    fn from_spki(spki: SubjectPublicKeyInfoRef<'_>, algorithm: String) -> Result<Self> {
        if algorithm != "ES384" {
            bail!("P384Verifier cannot verify requests signed with '{algorithm}'")
        }
        spki.try_into().map(Self).map_err(Error::from)
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        let signature = p384::ecdsa::Signature::from_slice(signature)?;
        self.0.verify(payload, &signature).map_err(Error::from)
    }
}

#[derive(Debug, Clone, Copy)]
enum RsaDigest {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone)]
pub struct RsaVerifier {
    key: RsaPublicKey,
    digest: RsaDigest,
}

impl Verifier for RsaVerifier {
    fn from_spki(spki: SubjectPublicKeyInfoRef<'_>, algorithm: String) -> Result<Self> {
        let digest = match algorithm.as_str() {
            "RS256" => RsaDigest::Sha256,
            "RS384" => RsaDigest::Sha384,
            "RS512" => RsaDigest::Sha512,
            other => bail!("RsaVerifier cannot verify requests signed with '{other}'"),
        };
        let key = RsaPublicKey::try_from(spki).map_err(Error::from)?;
        Ok(Self { key, digest })
    }

    fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<()> {
        let signature = RsaSignature::try_from(signature)?;
        match self.digest {
            RsaDigest::Sha256 => {
                RsaVerifyingKey::<Sha256>::new(self.key.clone()).verify(payload, &signature)
            }
            RsaDigest::Sha384 => {
                RsaVerifyingKey::<Sha384>::new(self.key.clone()).verify(payload, &signature)
            }
            RsaDigest::Sha512 => {
                RsaVerifyingKey::<Sha512>::new(self.key.clone()).verify(payload, &signature)
            }
        }
        .map_err(Error::from)
    }
}
