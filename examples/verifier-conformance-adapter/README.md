# OID4VP Verifier Adapter

Verifier implementation for OpenID for Verifiable Presentations (OID4VP) 1.0 conformance testing. Uses the `x509_san_dns` client ID scheme with a CA-signed leaf certificate.

## Features

- **X.509 SAN DNS**: Leaf certificate (domain as SAN) signed by a self-signed CA. Only the leaf is sent in `x5c`; the CA is provided to the suite as the request object trust anchor.
- **DCQL queries**: Requests SD-JWT VC credentials
- **Response modes**: `direct_post` and `direct_post.jwt` (JWE encrypted)
- **Response verification**: Minimal SD-JWT VC checks (issuer signature, KB-JWT signature, `sd_hash`, `nonce`, `aud`, `iat` freshness); rejects invalid presentations with a 4xx
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

# For the HAIP profile (x509_hash client ID + encrypted response)
cargo run --example verifier-conformance-adapter -- --public-url https://YOUR_NGROK_URL.ngrok-free.app --response-mode direct_post.jwt --client-id-prefix x509_hash
```

The adapter prints the signing key configuration on startup - you'll need this for the OIDF test setup.

### 3. Verify

```bash
curl https://YOUR_NGROK_URL.ngrok-free.app/health
```

## Conformance Tool Setup

Go to https://demo.certification.openid.net/ and create a new test plan.

### Test Configuration

| Field                 | Value                                                            |
| --------------------- | ---------------------------------------------------------------- |
| **Test Plan**         | `OpenID for Verifiable Presentations 1.0 Final: Test a verifier` |
| **Credential Format** | `sd_jwt_vc`                                                      |
| **Client Id Scheme**  | `x509_san_dns` (base) or `x509_hash` (HAIP)                      |
| **Response Mode**     | `direct_post` or `direct_post.jwt`                               |
| **VP Profile**        | `plain_vp` (base) or `haip`                                      |

### HAIP profile

For the `haip` VP profile, run with `--client-id-prefix x509_hash --response-mode direct_post.jwt`. This makes the adapter:

- use the `x509_hash` Client Identifier Prefix (`client_id = x509_hash:<base64url SHA-256 of the leaf cert>`), as HAIP Section 5 mandates;
- advertise `encrypted_response_enc_values_supported: ["A128GCM", "A256GCM"]` in `client_metadata` (required by HAIP Section 5);
- send encrypted responses via `direct_post.jwt`.

The `request_object_trust_anchor_pem` (see below) is still required so the suite can validate the leaf certificate's chain.

### Sample Configuration

Use the values printed by the adapter on startup:

```json
{
  "alias": "my-verifier-oid4vp1",
  "description": "OID4VP 1.0 Final verifier conformance - SD-JWT VC, x509_san_dns, request_uri_signed, direct_post",
  "client": {
    "client_id": "YOUR_NGROK_URL.ngrok-free.app",
    "request_object_trust_anchor_pem": "<from adapter output>"
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

#### `request_object_trust_anchor_pem`

The trust anchor certificate (PEM) the suite uses to verify the x5c chain of the
verifier's signed request object. **Required for HAIP.**

The adapter signs the request object with a leaf certificate (sent in the `x5c`
header) that is issued by a self-signed CA. That CA is the trust anchor: the
adapter prints it on startup as a ready-to-paste JSON property. Because this is a
JSON string value, the newlines are escaped as `\n` (the suite un-escapes them
when parsing) — this is expected, not a formatting bug.

The CA is cached per domain (`.cache/certs/<domain>.json`), so it stays stable
across restarts. If the public URL (domain) changes, the leaf and CA are
regenerated, so re-copy **both** the `signing_jwk` and
`request_object_trust_anchor_pem` from the banner.

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

| Endpoint                 | Method | Description                           |
| ------------------------ | ------ | ------------------------------------- |
| `/initiate`              | POST   | Start a new authorization request     |
| `/request/{session_id}`  | GET    | Wallet fetches the signed request JWT |
| `/response/{session_id}` | POST   | Wallet submits the VP token           |
| `/status/{session_id}`   | GET    | Check session status                  |
| `/health`                | GET    | Health check                          |

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
