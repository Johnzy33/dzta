#!/bin/bash

# Target Configuration
NAMESPACE="test-network"
OUTPUT_DIR="./config/certs"

echo "=== Creating local directory layout ==="
mkdir -p "$OUTPUT_DIR/cas" "$OUTPUT_DIR/peers" "$OUTPUT_DIR/orderers"

echo "=== Pulling Admin Identity and CA Certs ==="
# Pulling Org1 CA TLS Root Certificate
kubectl get secret org1-ca-tls-cert -n $NAMESPACE -o jsonpath='{.data.tls\.crt}' | base64 --decode > "$OUTPUT_DIR/cas/org1-ca-tls.crt"

# Pulling Admin identity credentials from the CA issuer secret (assuming standard test-network setup)
kubectl get secret org1-tls-cert-issuer-secret -n $NAMESPACE -o jsonpath='{.data.tls\.crt}' | base64 --decode > "$OUTPUT_DIR/cas/admin-cert.crt"
kubectl get secret org1-tls-cert-issuer-secret -n $NAMESPACE -o jsonpath='{.data.tls\.key}' | base64 --decode > "$OUTPUT_DIR/cas/admin-key.key"

echo "=== Pulling Peer TLS CA Certificates ==="
# Extracting the root trust CA bundle from the peer TLS secrets
kubectl get secret org1-peer1-tls-cert -n $NAMESPACE -o jsonpath='{.data.tls\.crt}' | base64 --decode > "$OUTPUT_DIR/peers/org1-peer1-tls-ca.crt"
kubectl get secret org1-peer2-tls-cert -n $NAMESPACE -o jsonpath='{.data.tls\.crt}' | base64 --decode > "$OUTPUT_DIR/peers/org1-peer2-tls-ca.crt"

echo "=== Pulling Orderer TLS CA Certificates ==="
# Using Orderer Node 1 as our primary orderer TLS root CA
kubectl get secret org0-orderer1-tls-cert -n $NAMESPACE -o jsonpath='{.data.tls\.crt}' | base64 --decode > "$OUTPUT_DIR/orderers/tls-ca.crt"

echo "=== Mapping Network Endpoints ==="
# Check if an Ingress or Service hostname exists, otherwise fall back to localho.st mapping
PEER1_HOST=$(kubectl get ingress org1-peer1 -n $NAMESPACE -o jsonpath='{.spec.rules[0].host}' 2>/dev/null || echo "peer1-org1.localho.st")
PEER2_HOST=$(kubectl get ingress org1-peer2 -n $NAMESPACE -o jsonpath='{.spec.rules[0].host}' 2>/dev/null || echo "peer2-org1.localho.st")

echo "=== Generating connection-profile.yaml ==="

cat <<EOF > connection-profile.yaml
name: "hlf-network"
version: "1.0"

client:
  organization: Org1MSP
  credentialStore:
    path: "/tmp/wallet"
    cryptoStore:
      path: "/tmp/msp"
  tlsCerts:
    client:
      key:
        path: "config/certs/cas/admin-key.key"
      cert:
        path: "config/certs/cas/admin-cert.crt"

organizations:
  Org1MSP:
    mspid: Org1MSP
    cryptoPath: /tmp/cryptopath
    peers:
      - org1-peer1-6c5b59dfb7-pbjvk
      - org1-peer2-64b8fb6576-7kxv9
    certificateAuthorities:
      - org1-ca-77458558f6-nh8z7
    users:
      admin:
        cert:
          path: "config/certs/cas/admin-cert.crt"
        key:
          path: "config/certs/cas/admin-key.key"

  OrdererMSP:
    mspid: OrdererMSP
    cryptoPath: /tmp/cryptopath
    orderers:
      - org0-orderer1.test-network
      - org0-orderer2.test-network
      - org0-orderer3.test-network

peers:
  org1-peer1.test-network:
    url: "grpcs://${PEER1_HOST}:443"
    grpcOptions:
      ssl-target-name-override: "${PEER1_HOST}"
      allow-insecure: false
    tlsCACerts:
      path: "config/certs/peers/org1-peer1-tls-ca.crt"

  org1-peer2.test-network:
    url: "grpcs://${PEER2_HOST}:443"
    grpcOptions:
      ssl-target-name-override: "${PEER2_HOST}"
      allow-insecure: false
    tlsCACerts:
      path: "config/certs/peers/org1-peer2-tls-ca.crt"

orderers:
  org0-orderer1.test-network:
    url: "grpcs://orderer1-org0.localho.st:443"
    grpcOptions:
      ssl-target-name-override: "orderer1-org0.localho.st"
      allow-insecure: false
    tlsCACerts:
      path: "config/certs/orderers/tls-ca.crt"

  org0-orderer2.test-network:
    url: "grpcs://orderer2-org0.localho.st:443"
    grpcOptions:
      ssl-target-name-override: "orderer2-org0.localho.st"
      allow-insecure: false
    tlsCACerts:
      path: "config/certs/orderers/tls-ca.crt"

  org0-orderer3.test-network:
    url: "grpcs://orderer3-org0.localho.st:443"
    grpcOptions:
      ssl-target-name-override: "orderer3-org0.localho.st"
      allow-insecure: false
    tlsCACerts:
      path: "config/certs/orderers/tls-ca.crt"

certificateAuthorities:
  org1-ca.test-network:
    url: "https://org1-ca.localho.st:443"
    caName: ca
    tlsCACerts:
      path: "config/certs/cas/org1-ca-tls.crt"
    registrar:
      enrollId: enroll
      enrollSecret: enrollpw
    httpOptions:
      verify: false

channels:
  demo:
    orderers:
      - org0-orderer1.test-network
      - org0-orderer2.test-network
      - org0-orderer3.test-network
    peers:
      org1-peer1.test-network:
        endorsingPeer: true
        chaincodeQuery: true
        ledgerQuery: true
        eventSource: true
      org1-peer2.test-network:
        endorsingPeer: true
        chaincodeQuery: true
        ledgerQuery: true
        eventSource: true
EOF

echo "✓ Generation complete. connection-profile.yaml is ready."
