#!/usr/bin/env bash

# Set target namespace
NAMESPACE="test-network"
OUTPUT_FILE="connection-profile.yaml"

echo "Extracting live cluster network details from namespace: ${NAMESPACE}..."

# 1. Fetch live Peer domain/service names
# Looks for services belonging to org1-peer1 or org2-peer1
PEER1_SVC=$(kubectl get svc -n ${NAMESPACE} -l app=org1-peer1 -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
PEER1_HOST="${PEER1_SVC}.${NAMESPACE}.svc.cluster.local"

# Fallback defaults if services aren't uniquely labeled yet
if [ -z "$PEER1_SVC" ]; then
    PEER1_HOST="org1-peer1.${NAMESPACE}.svc.cluster.local"
fi

# 2. Extract dynamic list of Orderer services running inside the namespace
ORDERERS_JSON=$(kubectl get svc -n ${NAMESPACE} -l app=org0-orderer -o jsonpath='{.items[*].metadata.name}' 2>/dev/null)
if [ -z "$ORDERERS_JSON" ]; then
    # Fallback to structural extraction if labels vary
    ORDERER_LIST=("org0-orderer1" "org0-orderer2" "org0-orderer3")
else
    read -r -a ORDERER_LIST <<< "$ORDERERS_JSON"
fi

# 3. Build YAML arrays dynamically for Orderers
YAML_ORG_ORDERERS=""
YAML_CHANNEL_ORDERERS=""
YAML_ORDERERS_CONFIG=""

for ORD in "${ORDERER_LIST[@]}"; do
    ORD_HOST="${ORD}.${NAMESPACE}.svc.cluster.local"
    
    # Append to organization list
    YAML_ORG_ORDERERS="${YAML_ORG_ORDERERS}\n      - ${ORD}.${NAMESPACE}"
    
    # Append to channel list
    YAML_CHANNEL_ORDERERS="${YAML_CHANNEL_ORDERERS}\n      - ${ORD}.${NAMESPACE}"
    
    # Append to main definition block (using default HLF port 6050 or 7050 depending on setup)
    YAML_ORDERERS_CONFIG="${YAML_ORDERERS_CONFIG}
  ${ORD}.${NAMESPACE}:
    url: \"grpcs://${ORD_HOST}:6050\"
    grpcOptions:
      ssl-target-name-override: \"${ORD_HOST}\"
      allow-insecure: false
    tlsCACerts:
      path: \"config/certs/orderers/tls-ca.crt\"
"
done

# 4. Fetch CA service name
CA_SVC=$(kubectl get svc -n ${NAMESPACE} -l app=org1-ca -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
[ -z "$CA_SVC" ] && CA_SVC="org1-ca"
CA_HOST="${CA_SVC}.${NAMESPACE}.svc.cluster.local"


# Write out the dynamically constructed configuration matrix
cat << EOF > ${OUTPUT_FILE}
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
      - org1-peer1.${NAMESPACE}
    certificateAuthorities:
      - ${CA_SVC}.${NAMESPACE}

  OrdererMSP:
    mspid: OrdererMSP
    cryptoPath: /tmp/cryptopath
    orderers:$(echo -e "${YAML_ORG_ORDERERS}")

peers:
  org1-peer1.${NAMESPACE}:
    url: "grpcs://${PEER1_HOST}:7051"
    grpcOptions:
      ssl-target-name-override: "${PEER1_HOST}"
      allow-insecure: false
    tlsCACerts:
      path: "config/certs/peers/org1-peer1-tls-ca.crt"

orderers:
$(echo "${YAML_ORDERERS_CONFIG}")
certificateAuthorities:
  ${CA_SVC}.${NAMESPACE}:
    url: "https://${CA_HOST}:7054"
    caName: ca
    tlsCACerts:
      path: "config/certs/cas/org1-ca-tls.crt"
    registrar:
      enrollId: admin
      enrollSecret: adminpw
    httpOptions:
      verify: false

channels:
  dzta:
    orderers:$(echo -e "${YAML_CHANNEL_ORDERERS}")
    peers:
      org1-peer1.${NAMESPACE}:
        endorsingPeer: true
        chaincodeQuery: true
        ledgerQuery: true
        eventSource: true
EOF

echo "✅ Generation complete! Saved to ${OUTPUT_FILE}"