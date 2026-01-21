# OID4VP Wallet Adapter

Headless wallet for OpenID for Verifiable Presentations (OID4VP) 1.0 conformance testing. Automatically responds to authorization requests using pre-configured SD-JWT credentials.

## Features

- **Headless operation**: No user interaction required
- **SD-JWT VC**: `dc+sd-jwt` and `vc+sd-jwt` formats with Key Binding JWT
- **DCQL queries**: Digital Credentials Query Language support
- **Response modes**: `direct_post` and `direct_post.jwt` (JWE encrypted)

## Quick Start

### 1. Start ngrok tunnel

```bash
ngrok http 3000
```

### 2. Run the wallet adapter

```bash
cargo run -p oid4vp-wallet-adapter -- --public-url https://YOUR_NGROK_URL.ngrok-free.app
```

### 3. Verify

```bash
curl https://YOUR_NGROK_URL.ngrok-free.app/health
```

## Conformance Tool Setup

Go to https://demo.certification.openid.net/ and create a new test plan.

### Test Configuration

| Field | Value |
|-------|-------|
| **Test Plan** | `OpenID for Verifiable Presentations 1.0 Final: Test a wallet` |
| **Credential Format** | `sd_jwt_vc` |
| **Client Id Prefix** | `redirect_uri` |
| **Request Method** | `request_uri_unsigned` |
| **Response Mode** | `direct_post` or `direct_post.jwt` |

### Sample Configuration

```json
{
  "alias": "my-wallet-oid4vp1",
  "description": "OID4VP 1.0 Final wallet conformance - headless SD-JWT VC, redirect_uri, request_uri_unsigned, direct_post",
  "server": {
    "authorization_endpoint": "https://44299586d955.ngrok-free.app/authorize"
  },
  "client": {
    "client_id_prefix": "redirect_uri",
    "response_mode": "direct_post",
    "request_method": "request_uri_unsigned",
    "authorization_encrypted_response_alg": "ECDH-ES",
    "authorization_encrypted_response_enc": "A256GCM",
    "dcql": {
      "credentials": [
        {
          "id": "cred1",
          "format": "dc+sd-jwt",
          "meta": {
            "vct_values": ["https://credentials.example.com/pid/1.0"]
          }
        }
      ]
    },
    "jwks": {
      "keys": [
        {
          "kty": "EC",
          "crv": "P-256",
          "d": "r1fMPK1DVLTIENnv9BJZfYGHeaPuOtM6b7QhnTv3GTo",
          "x": "gFqG6qohoNqGa6_Pih78BKLLCZYrZoZhzad3hIvaDoU",
          "y": "BQpmQ1bkmb4fm0Z187reLUEKt-Hbw9FXANNaaEm0ZYM",
          "kid": "conformance-test-key",
          "use": "sig",
          "alg": "ES256"
        }
      ]
    }
  }
}
```

### Running Tests

After starting a test, open the authorization URL in Firefox (not Chrome - it may send duplicate requests causing failures).

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET/POST /authorize` | Authorization endpoint |
| `GET /.well-known/openid-configuration` | Wallet metadata |
| `GET /.well-known/jwks.json` | Public keys (JWKS) |
| `GET /health` | Health check |
| `GET /debug/credentials` | List mock credentials |

## Mock Credentials

| Credential | Format | VCT |
|------------|--------|-----|
| PID Credential | `dc+sd-jwt` | `https://credentials.example.com/pid/1.0` |

## Development

```bash
# Debug logging
RUST_LOG=debug cargo run -p oid4vp-wallet-adapter -- --public-url https://YOUR_NGROK_URL.ngrok-free.app
```
