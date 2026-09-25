ui = true
disable_mlock = true # Set to true for non-root local user execution on Arch

storage "raft" {
  path    = "./vault/data"
  node_id = "dzta-local-node"
}

listener "tcp" {
  address       = "127.0.0.1:8200"
  tls_cert_file = "./vault/tls/vault-cert.pem"
  tls_key_file  = "./vault/tls/vault-key.pem"
}

api_addr     = "https://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"