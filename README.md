# OpenID for Verifiable Presentations (OID4VP)

[![Crates.io](https://img.shields.io/crates/v/openid4vp)](https://crates.io/crates/openid4vp)
[![Docs.rs](https://docs.rs/openid4vp/badge.svg)](https://docs.rs/openid4vp)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Rust implementation of the OpenID for Verifiable Presentations (OID4VP) specification.

<!-- cargo-rdme start -->
<!-- cargo-rdme end -->

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

Ensure the `/tests/presentation-exchange` submodule is initialized by running the following in the root of the project:

```shell
git submodule init --recursive
```

## Protocol Flow Diagram

```mermaid
sequenceDiagram
    participant Wallet
    participant Verifier
    participant Issuer

    Verifier->>Wallet: 1. Authorization Request (Presentation Definition/DCQL)
    Note over Wallet: 2. User consents to share credentials
    Wallet->>Wallet: 3. Select appropriate credentials
    Wallet->>Wallet: 4. Create Verifiable Presentation
    Wallet->>Wallet: 5. Create Presentation Submission
    Wallet->>Verifier: 6. Authorization Response (VP Token + Submission)
    Verifier->>Verifier: 7. Validate VP Token signatures
    Verifier->>Issuer: 8. (Optional) Verify credential status
    Issuer-->>Verifier: 9. (Optional) Credential status response
    Verifier->>Verifier: 10. Verify claims against Presentation Definition
    Verifier->>Wallet: 11. Grant or deny access based on verification
```

## Examples

Check the [`examples`](examples/) directory for complete implementations:
- [`cli-verifier`](examples/cli-verifier/): Command-line verifier for testing OID4VP flows
- [`verifier-conformance-adapter`](examples/verifier-conformance-adapter/): Conformance testing adapter
- [`oid4vp-wallet-adapter`](examples/oid4vp-wallet-adapter/): Headless wallet adapter

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
