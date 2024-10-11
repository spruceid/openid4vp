# OpenID for Verifiable Presentations (OID4VP)

[![Crates.io](https://img.shields.io/crates/v/oid4vp)](https://crates.io/crates/oid4vp)
[![Docs.rs](https://docs.rs/oid4vp/badge.svg)](https://docs.rs/oid4vp)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

### Rust implementation of the OpenID for Verifiable Presentations (OID4VP) specification.


## Install

Add the following to your `Cargo.toml`:

```toml
[dependencies]
openid4vp = "0.1"
```

or

```shell
cargo add openid4vp
```

## Testing

Ensure the `/tests/presentation-exchange` submodule is initialized, run the following in the root of the project:

```shell
git submodule init --recursive
```


## Presentation Exchange Overview

```mermaid
sequenceDiagram
    participant Holder
    participant Verifier
    participant Issuer

    Verifier->>Holder: 1. Request Presentation (with Presentation Definition)
    Note over Holder: 2. User consents to share credentials
    Holder->>Holder: 3. Select appropriate credentials
    Holder->>Holder: 4. Create Verifiable Presentation
    Holder->>Holder: 5. Create Presentation Submission
    Holder->>Verifier: 6. Send VP Token (VP + Presentation Submission)
    Verifier->>Verifier: 7. Validate VP Token
    Verifier->>Issuer: 8. (Optional) Verify credential status
    Issuer-->>Verifier: 9. (Optional) Credential status response
    Verifier->>Verifier: 10. Check claims against Presentation Definition
    Verifier->>Holder: 11. Grant or deny access based on verification
```


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
