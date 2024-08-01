/// A credential format that can be transmitted using OID4VP.
pub trait CredentialFormat {
    /// The ID of the credential format.
    const ID: &'static str;
}

pub struct MsoMdoc;

impl CredentialFormat for MsoMdoc {
    const ID: &'static str = "mso_mdoc";
}

pub struct JwtVc;

impl CredentialFormat for JwtVc {
    const ID: &'static str = "jwt_vc";
}
