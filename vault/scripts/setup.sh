#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${PROJECT_ROOT}"

export VAULT_ADDR="https://127.0.0.1:8200"
export VAULT_CACERT="${PROJECT_ROOT}/vault/tls/vault-cert.pem"

echo "==> Starting Vault Server..."
vault server -config=vault/config/vault.hcl > vault/vault.log 2>&1 &
SERVER_PID=$!
echo ${SERVER_PID} > vault/vault.pid

sleep 2

echo "==> Initializing Vault..."
vault operator init -key-shares=1 -key-threshold=1 -format=json > vault/scripts/vault-keys.json

UNSEAL_KEY=$(jq -r '.unseal_keys_b64[0]' vault/scripts/vault-keys.json)
ROOT_TOKEN=$(jq -r '.root_token' vault/scripts/vault-keys.json)

echo "==> Unsealing Vault..."
vault operator unseal "${UNSEAL_KEY}"

export VAULT_TOKEN="${ROOT_TOKEN}"

echo "==> Enabling Transit Secrets Engine..."
vault secrets enable transit

echo "==> Creating Credential Signing Key (Ed25519)..."
vault write -f transit/keys/dzta-credential-signing-key type=ed25519

echo "==> Creating Secret Release Encryption Key (AES256-GCM)..."
vault write -f transit/keys/dzta-secret-release-key type=aes256-gcm96

echo "==> Writing .env.vault file for dzta-issuer & dzta-attestation-broker..."
cat <<ENV > vault/scripts/.env.vault
export DZTA_VAULT_ADDR="${VAULT_ADDR}"
export DZTA_VAULT_TOKEN="${ROOT_TOKEN}"
export DZTA_CREDENTIAL_SIGNING_KEY="dzta-credential-signing-key"
export DZTA_SECRET_RELEASE_KEY="dzta-secret-release-key"
export VAULT_CACERT="${VAULT_CACERT}"
ENV

echo "==> Setup complete! Source the environment variables with:"
echo "    source vault/scripts/.env.vault"
