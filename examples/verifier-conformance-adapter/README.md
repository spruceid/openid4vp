# OID4VP Verifier Adapter

Verifier implementation for OpenID for Verifiable Presentations (OID4VP) 1.0 conformance testing. Uses `x509_san_dns` client ID scheme with self-signed certificates.

## Features

- **X.509 SAN DNS**: Self-signed certificate with domain as SAN
- **DCQL queries**: Requests SD-JWT VC credentials
- **Response modes**: `direct_post` and `direct_post.jwt` (JWE encrypted)
- **Certificate caching**: Reuses certificates for the same domain

## Quick Start

### 1. Start ngrok tunnel

```bash
ngrok http 3000
```

### 2. Run the verifier adapter

```bash
# For direct_post (unencrypted)
cargo run --example verifier-conformance-adapter -- --public-url https://YOUR_NGROK_URL.ngrok-free.app

# For direct_post.jwt (encrypted)
cargo run --example verifier-conformance-adapter -- --public-url https://YOUR_NGROK_URL.ngrok-free.app --response-mode direct_post.jwt
```

The adapter prints the signing key configuration on startup - you'll need this for the OIDF test setup.

### 3. Verify

```bash
curl https://YOUR_NGROK_URL.ngrok-free.app/health
```

## Conformance Tool Setup

Go to https://demo.certification.openid.net/ and create a new test plan.

### Test Configuration

| Field | Value |
|-------|-------|
| **Test Plan** | `OpenID for Verifiable Presentations 1.0 Final: Test a verifier` |
| **Credential Format** | `sd_jwt_vc` |
| **Client Id Scheme** | `x509_san_dns` |
| **Response Mode** | `direct_post` or `direct_post.jwt` |

### Sample Configuration

Use the values printed by the adapter on startup:

```json
{
    "alias": "my-verifier-oid4vp1",
    "description": "OID4VP 1.0 Final verifier conformance - SD-JWT VC, x509_san_dns, request_uri_signed, direct_post",
    "client": {
        "client_id": "YOUR_NGROK_URL.ngrok-free.app"
    },
    "credential": {
        "signing_jwk": {
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "x": "<from adapter output>",
            "y": "<from adapter output>",
            "d": "<from adapter output>",
            "x5c": ["<from adapter output>"]
        }
    },
    "federation": {
        "trust_anchor": "https://demo.certification.openid.net/test/a/my-verifier-oid4vp1/trust-anchor"
    }
}
```

## Running Tests (Manual Flow)

Unlike the wallet adapter, the verifier tests require manual interaction:

### Step 1: Start a test in OIDF

Click "Start" on a test case in the OIDF conformance suite.

### Step 2: Initiate an authorization request

```bash
curl -s -X POST https://YOUR_NGROK_URL.ngrok-free.app/initiate \
  -H "Content-Type: application/json" \
  -d '{}'
```

Response:
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "authorization_url": "https://demo.certification.openid.net/test/a/my-verifier-oid4vp1/authorize?client_id=...",
  "status_url": "https://YOUR_NGROK_URL.ngrok-free.app/status/550e8400-e29b-41d4-a716-446655440000"
}
```

### Step 3: Open authorization URL in Firefox

Copy `authorization_url` and paste it into Firefox (not Chrome - it may send duplicate requests).

The OIDF test wallet will process the request and send the VP token back to your adapter.

### Step 4: Check status (optional)

```bash
curl https://YOUR_NGROK_URL.ngrok-free.app/status/SESSION_ID
```

### Step 5: Verify test result in OIDF

Go back to the OIDF conformance tool and check if the test passed.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/initiate` | POST | Start a new authorization request |
| `/request/{session_id}` | GET | Wallet fetches the signed request JWT |
| `/response/{session_id}` | POST | Wallet submits the VP token |
| `/status/{session_id}` | GET | Check session status |
| `/health` | GET | Health check |

## Development

```bash
# Debug logging
RUST_LOG=debug cargo run --example verifier-conformance-adapter -- --public-url https://YOUR_NGROK_URL.ngrok-free.app

# With encrypted responses
RUST_LOG=debug cargo run --example verifier-conformance-adapter -- \
  --public-url https://YOUR_NGROK_URL.ngrok-free.app \
  --response-mode direct_post.jwt
```

## Certificate Caching

The adapter caches generated certificates in `verifier-conformance-adapter/.cache/certs/`. Delete this directory to force regeneration.