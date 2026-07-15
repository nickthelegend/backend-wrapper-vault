# backend-wrapper-vault

> **A custodial Algorand signing service that keeps per-user private keys inside HashiCorp Vault — clients authenticate with Google OAuth and never touch a seed phrase.**

## Overview

`backend-wrapper-vault` is a small Express API that lets a web or mobile app sign and submit Algorand transactions on a user's behalf without ever exposing a private key to the client. Each user gets a dedicated `ed25519` key created inside HashiCorp Vault's [Transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit); the server derives the user's Algorand address from that key's public bytes, verifies the caller with a Google OAuth token, asks Vault to sign the canonical transaction bytes, attaches the signature, and broadcasts the result to Algorand TestNet.

It's built for developers exploring account-abstraction / social-login wallet flows on Algorand, where the goal is a keyless client experience with signing kept server-side behind Vault.

## Features

- **Vault-backed custodial keys** — creates a per-user `ed25519` Transit key (`algo-user-<uid>`) plus a scoped ACL policy that can only sign and read that one key.
- **Google OAuth verification** — validates the caller's access token against Google's `tokeninfo` endpoint and checks the audience against the configured client ID (a `mockToken` shortcut is available for local testing).
- **Ephemeral, least-privilege tokens** — `/create` issues a short-lived (default 30m) Vault token scoped to the user's signing policy.
- **Deterministic address derivation** — `/get/:id` reads the Transit public key and encodes it into a standard Algorand address.
- **Sign-only and sign-and-submit flows** — `/sign` and `/sign-txn` accept base64 transaction bytes, sign them via Vault Transit, and broadcast the signed transaction to Algorand TestNet via AlgoNode.
- **Built-in mock flow** — `/mock` builds, signs, and submits a 1-ALGO test payment end-to-end for quick verification.

### API Endpoints

| Method | Path         | Description                                             |
| ------ | ------------ | ------------------------------------------------------- |
| `POST` | `/create`    | Create the user's Transit key, ACL policy, and ephemeral token |
| `POST` | `/sign`      | Sign a base64 transaction and submit it to TestNet      |
| `POST` | `/sign-txn`  | Sign raw unsigned-transaction bytes and submit them      |
| `GET`  | `/get/:id`   | Derive the Algorand address for a user's Vault key       |
| `GET`  | `/mock`      | Run a full create/sign/submit test payment               |
| `GET`  | `/`          | Health check                                            |

## Tech Stack

- **Runtime:** Node.js (ES modules)
- **Web framework:** Express 5
- **Blockchain SDK:** algosdk 3 (Algorand TestNet via AlgoNode)
- **Key management:** HashiCorp Vault — Transit secrets engine
- **Auth:** Google OAuth 2.0 token verification
- **HTTP client:** axios

## Getting Started

### Prerequisites

- Node.js 18+
- A running HashiCorp Vault instance with the Transit engine enabled
- A Google OAuth client ID (for real token verification)

### Install & run

```bash
# Install dependencies
npm install

# Configure environment (defaults shown)
export VAULT_ADDR="http://localhost:8200"
export VAULT_TOKEN="root"
export VAULT_ADMIN_TOKEN="root"
export GOOGLE_CLIENT_ID="<your-google-oauth-client-id>"
export EPHEMERAL_TTL="30m"

# Start the server (listens on :3000)
npm start
```

### Quick test

With the server running, hit the mock end-to-end flow or use the included test scripts:

```bash
# Full create/sign/submit test payment
curl http://127.0.0.1:3000/mock

# Sign a base64 transaction with the mock OAuth token
node test-request.js
```

## Project Structure

```
.
├── server.js                    # Express app: /create, /sign, /sign-txn, /get/:id, /mock
├── sad.js                       # Helper: derive Algorand address from a Vault Transit key
├── generate-base64.js           # Helper: base64-encode a sample txn + build a curl command
├── test-request.js              # Simple /sign request test
├── sign-vault-transaction.bat   # Windows curl example for /sign
├── test-sign.bat                # Windows curl example for /sign
├── package.json
└── package-lock.json
```

## Notes

This is an experimental backend for a Vault-based Algorand signing flow and targets Algorand **TestNet**. The default Vault tokens (`root`) and permissive CORS are development conveniences — harden Vault tokens, authentication, and network exposure before any production use.

---

Built by [nickthelegend](https://github.com/nickthelegend) · [nickthelegend.tech](https://nickthelegend.tech)
