use anyhow::Result;
#[cfg(feature = "p256")]
use anyhow::{bail, Error};
#[cfg(feature = "p256")]
use p256::ecdsa::signature::Verifier as _;
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

#[cfg(feature = "p256")]
#[derive(Debug, Clone)]
pub struct P256Verifier(p256::ecdsa::VerifyingKey);

#[cfg(feature = "p256")]
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
