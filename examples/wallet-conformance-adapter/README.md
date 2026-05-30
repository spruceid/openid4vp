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
cargo run --example wallet-conformance-adapter -- --public-url https://YOUR_NGROK_URL.ngrok-free.app
```

### 3. Verify

```bash
curl https://YOUR_NGROK_URL.ngrok-free.app/health
```

## Conformance Tool Setup

Go to https://demo.certification.openid.net/ and create a new test plan.

### Test Configuration

| Field                 | Value                                                          |
| --------------------- | -------------------------------------------------------------- |
| **Test Plan**         | `OpenID for Verifiable Presentations 1.0 Final: Test a wallet` |
| **Credential Format** | `sd_jwt_vc`                                                    |
| **Client Id Prefix**  | `redirect_uri` (base) or `x509_hash` (HAIP)                    |
| **Request Method**    | `request_uri_unsigned` (base) or `request_uri_signed` (HAIP)   |
| **Response Mode**     | `direct_post` or `direct_post.jwt`                             |
| **VP Profile**        | `plain_vp` (base) or `haip`                                    |

### Sample Configuration

```json
{
  "alias": "my-wallet-oid4vp1",
  "description": "OID4VP 1.0 Final wallet conformance - headless SD-JWT VC, redirect_uri, request_uri_unsigned, direct_post",
  "server": {
    "authorization_endpoint": "https://YOUR_NGROK_URL.ngrok-free.app/authorize"
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
          },
          "claims": [
            { "path": ["given_name"] },
            { "path": ["family_name"] },
            { "path": ["nationality"] },
            { "path": ["age_over_18"] }
          ]
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

### HAIP profile configuration

For the `haip` VP profile the variant is `x509_hash` / `request_uri_signed` / `direct_post.jwt`. In a wallet test the conformance suite acts as the **verifier** and signs the request object, so the `client.jwks` signing key MUST carry an `x5c` certificate chain (HAIP Section 5 also requires the leaf to be CA-signed, i.e. not self-signed). The default sample key above has no `x5c`, which fails with `SetClientIdToX509Hash: ... the signing key in the client jwks ... doesn't have an x5c entry`.

Use this config instead (the key below is a CA-signed leaf; the CA is given afterwards as the wallet's trust anchor):

```json
{
  "alias": "my-wallet-oid4vp1",
  "description": "OID4VP 1.0 Final wallet conformance - HAIP SD-JWT VC, x509_hash, request_uri_signed, direct_post.jwt",
  "server": {
    "authorization_endpoint": "https://YOUR_NGROK_URL.ngrok-free.app/authorize"
  },
  "client": {
    "client_id_prefix": "x509_hash",
    "request_method": "request_uri_signed",
    "response_mode": "direct_post.jwt",
    "authorization_encrypted_response_alg": "ECDH-ES",
    "authorization_encrypted_response_enc": "A256GCM",
    "dcql": {
      "credentials": [
        {
          "id": "cred1",
          "format": "dc+sd-jwt",
          "meta": {
            "vct_values": ["https://credentials.example.com/pid/1.0"]
          },
          "claims": [
            { "path": ["given_name"] },
            { "path": ["family_name"] },
            { "path": ["nationality"] },
            { "path": ["age_over_18"] }
          ]
        }
      ]
    },
    "jwks": {
      "keys": [
        {
          "kty": "EC",
          "crv": "P-256",
          "d": "O3oF9vyix0iQsXDGAsHLgfM55I7HqPIL6Y9xkLJJsHU",
          "x": "k85V0J-TvX4gmMT_C-hOgqZNR3jnk4bNr1aBfmR8vqw",
          "y": "pb0HQW7d08BnJOrjbX92A63ZFksl0_4Yj5oBLtz41rc",
          "kid": "conformance-test-key",
          "use": "sig",
          "alg": "ES256",
          "x5c": [
            "MIIB1jCCAXugAwIBAgIUVjuNa1Q/Su/k4mVVls7wowAhbyEwCgYIKoZIzj0EAwIwTTELMAkGA1UEBhMCQlIxGTAXBgNVBAoMEENvbmZvcm1hbmNlIFRlc3QxIzAhBgNVBAMMGk9JRDRWUCBDb25mb3JtYW5jZSBUZXN0IENBMCAXDTI2MDUyOTE5NTEwOFoYDzIxMjYwNTA1MTk1MTA4WjBCMQswCQYDVQQGEwJCUjEZMBcGA1UECgwQQ29uZm9ybWFuY2UgVGVzdDEYMBYGA1UEAwwPT0lENFZQIFZlcmlmaWVyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEk85V0J+TvX4gmMT/C+hOgqZNR3jnk4bNr1aBfmR8vqylvQdBbt3TwGck6uNtf3YDrdkWSyXT/hiPmgEu3PjWt6NCMEAwHQYDVR0OBBYEFL0dHtuSYzXnrFxJA9CGFgJ4yoODMB8GA1UdIwQYMBaAFNnEtUYZ0L6IyEYuLNUz9hf9PCqfMAoGCCqGSM49BAMCA0kAMEYCIQDhdP2g9bw8ySHU3/HS0ls4CnM2WZgdVrMn+kUHmuYCrgIhAKhrIfV/Ag84vlgy30pqlqSs36DWRulHRHCRkKX4ry9+"
          ]
        }
      ]
    }
  },
  "credential": {
    "trust_anchor_pem": "-----BEGIN CERTIFICATE-----\nMIIBxzCCAWygAwIBAgIUEAJqpjLRGxVMcRN2IgsiqpVlNokwCgYIKoZIzj0EAwIw\nSDEeMBwGA1UEAwwVT0lENFZQIElzc3VlciBUZXN0IENBMRkwFwYDVQQKDBBDb25m\nb3JtYW5jZSBUZXN0MQswCQYDVQQGDAJCUjAgFw03NTAxMDEwMDAwMDBaGA80MDk2\nMDEwMTAwMDAwMFowSDEeMBwGA1UEAwwVT0lENFZQIElzc3VlciBUZXN0IENBMRkw\nFwYDVQQKDBBDb25mb3JtYW5jZSBUZXN0MQswCQYDVQQGDAJCUjBZMBMGByqGSM49\nAgEGCCqGSM49AwEHA0IABPGp7fgd/ysv1nen+8mb3nh0fyazE3BD2ixN1ccv15Yz\ngSmef7QRQZlqX+nDVoUl08vbadeae4m8R7XviEewnBSjMjAwMB0GA1UdDgQWBBTh\nGZAX0q9N8UdcjeUgtG2Z85JwGzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMC\nA0kAMEYCIQDfhmQQjf6xWIm2nxsOY0PoA23wL1Fqc9q9mITpCSjQBgIhAJ1O7CWM\nGjhfItLbkm/vTpZxeGjAKqQ7xbV8vqa2VGaK\n-----END CERTIFICATE-----",
    "status_list_trust_anchor_pem": "-----BEGIN CERTIFICATE-----\nMIIBxzCCAWygAwIBAgIUEAJqpjLRGxVMcRN2IgsiqpVlNokwCgYIKoZIzj0EAwIw\nSDEeMBwGA1UEAwwVT0lENFZQIElzc3VlciBUZXN0IENBMRkwFwYDVQQKDBBDb25m\nb3JtYW5jZSBUZXN0MQswCQYDVQQGDAJCUjAgFw03NTAxMDEwMDAwMDBaGA80MDk2\nMDEwMTAwMDAwMFowSDEeMBwGA1UEAwwVT0lENFZQIElzc3VlciBUZXN0IENBMRkw\nFwYDVQQKDBBDb25mb3JtYW5jZSBUZXN0MQswCQYDVQQGDAJCUjBZMBMGByqGSM49\nAgEGCCqGSM49AwEHA0IABPGp7fgd/ysv1nen+8mb3nh0fyazE3BD2ixN1ccv15Yz\ngSmef7QRQZlqX+nDVoUl08vbadeae4m8R7XviEewnBSjMjAwMB0GA1UdDgQWBBTh\nGZAX0q9N8UdcjeUgtG2Z85JwGzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMC\nA0kAMEYCIQDfhmQQjf6xWIm2nxsOY0PoA23wL1Fqc9q9mITpCSjQBgIhAJ1O7CWM\nGjhfItLbkm/vTpZxeGjAKqQ7xbV8vqa2VGaK\n-----END CERTIFICATE-----"
  }
}
```

The `credential` block is a top-level key (sibling of `server` and `client`), placed last before the closing brace. Both PEMs are JSON strings, so the newlines are escaped as `\n`.

> **Note:** `trust_anchor_pem` is the **issuer CA** — the suite uses it to verify the SD-JWT VC the wallet presents. The wallet adapter uses a fixed (hardcoded) issuer key/CA, so the PEM above is the real value and works as-is (it is also printed on startup). The same CA is reused for `status_list_trust_anchor_pem`. The `x5c` inside `client.jwks` is unrelated — that is the _verifier's_ request-signing certificate, used by the suite to sign the request object.

### Running Tests

After starting a test, open the authorization URL in Firefox (not Chrome - it may send duplicate requests causing failures).

## Endpoints

| Endpoint                                | Description            |
| --------------------------------------- | ---------------------- |
| `GET/POST /authorize`                   | Authorization endpoint |
| `GET /.well-known/openid-configuration` | Wallet metadata        |
| `GET /.well-known/jwks.json`            | Public keys (JWKS)     |
| `GET /health`                           | Health check           |
| `GET /debug/credentials`                | List mock credentials  |

## Mock Credentials

| Credential     | Format      | VCT                                       |
| -------------- | ----------- | ----------------------------------------- |
| PID Credential | `dc+sd-jwt` | `https://credentials.example.com/pid/1.0` |

## Development

```bash
# Debug logging
RUST_LOG=debug cargo run --example wallet-conformance-adapter -- --public-url https://YOUR_NGROK_URL.ngrok-free.app
```
