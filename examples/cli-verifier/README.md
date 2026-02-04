# CLI Verifier

A minimal command-line verifier for testing OID4VP v1.0 protocol with mobile wallets.

## Features

- Generates QR codes for wallet scanning
- Supports multiple credential formats: mDL, LDP VC, JWT VC, VCDM2 SD-JWT
- Uses `redirect_uri` client_id_scheme (no certificates or DIDs required)
- Supports credential selection with OR logic via DCQL `credential_sets`

## Prerequisites

- A public URL accessible from the wallet (use [ngrok](https://ngrok.com/) for local testing)
- A mobile wallet that supports OID4VP v1.0

## Usage

```bash
# Start ngrok to expose local port
ngrok http 3000

# Run the verifier with your ngrok URL
cargo run --example cli-verifier -- --public-url https://your-url.ngrok.io
```

### CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --port` | Port to listen on | `3000` |
| `--public-url` | Public URL where the server is accessible (required) | - |
| `-c, --credential` | Credential types to request (comma-separated) | `mdl` |
| `--no-qr` | Disable QR code display | `false` |

### Credential Types

| Type | Description | Format |
|------|-------------|--------|
| `mdl` | Mobile Driver's License | `mso_mdoc` |
| `ldp_vc` | W3C VC with Data Integrity proof | `ldp_vc` |
| `jwt_vc` | W3C VC secured with JWT | `jwt_vc_json` |
| `vcdm2_sd_jwt` | W3C VCDM v2 with SD-JWT encoding | Custom format |
| `ldp_or_mdl` | Accept either LDP VC OR mDL | OR logic |

## Examples

### Request a single mDL

```bash
cargo run --example cli-verifier -- --public-url https://abc.ngrok.io -c mdl
```

### Request multiple credentials (AND logic)

All credentials are required:

```bash
cargo run --example cli-verifier -- --public-url https://abc.ngrok.io -c mdl,jwt_vc
```

This creates:
- `credential_sets[0]`: requires `mdl_0`
- `credential_sets[1]`: requires `jwt_vc_0`

Wallet must present **both** credentials.

### Request with OR logic

Accept either LDP VC or mDL:

```bash
cargo run --example cli-verifier -- --public-url https://abc.ngrok.io -c ldp_or_mdl
```

This creates:
- `credential_sets[0]`: options `[["ldp_vc_0"], ["mdl_0"]]`

Wallet can present **either** credential.

### Combine OR and AND logic

```bash
cargo run --example cli-verifier -- --public-url https://abc.ngrok.io -c ldp_or_mdl,jwt_vc
```

This creates:
- `credential_sets[0]`: options `[["ldp_vc_0"], ["mdl_0"]]` (OR)
- `credential_sets[1]`: options `[["jwt_vc_0"]]` (required)

Wallet must present **(LDP VC OR mDL) AND JWT VC**.

## Technical Notes

- Uses `redirect_uri` client_id_scheme per OID4VP v1.0 Section 5.9.3
- Authorization requests are unsigned (alg: "none") as required by spec
- Uses `by_reference` mode - wallet fetches request via GET
- Response mode is `direct_post`
- Per OID4VP v1.0 Appendix B, credential format identifiers (e.g., `jwt_vc_json`, `ldp_vc`) cover both credentials AND presentations