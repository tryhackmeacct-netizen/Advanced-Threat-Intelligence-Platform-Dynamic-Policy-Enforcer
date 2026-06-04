#!/usr/bin/env bash
set -euo pipefail

WORKDIR="$(cd "$(dirname "$0")/.." && pwd)"
CERT_DIR="$WORKDIR/generated_elastic_certs"
INSTALL_DIR="/etc/elasticsearch/certs"

ELASTICSEARCH_KEYSTORE="/usr/share/elasticsearch/bin/elasticsearch-keystore"
HTTP_KEYSTORE_PASSWORD=""

if sudo "$ELASTICSEARCH_KEYSTORE" list 2>/dev/null | grep -q '^xpack.security.http.ssl.keystore.secure_password$'; then
  HTTP_KEYSTORE_PASSWORD=$(sudo "$ELASTICSEARCH_KEYSTORE" show xpack.security.http.ssl.keystore.secure_password)
  echo "Detected existing Elasticsearch HTTP keystore secure password. The generated http.p12 will be created with this password."
else
  echo "No existing Elasticsearch HTTP keystore password detected. Generating a passwordless HTTP PKCS12 bundle."
fi

[ -d "$CERT_DIR" ] || mkdir -p "$CERT_DIR"

# Detect the publish IP to include in the SANs (fall back to first host IP)
PUBLISH_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {print $7; exit}')
if [ -z "$PUBLISH_IP" ]; then
  PUBLISH_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi

cat > "$CERT_DIR/openssl.cnf" <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Elasticsearch
OU = Elasticsearch
CN = localhost

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = sanket-VMware-Virtual-Platform
IP.1 = 127.0.0.1
EOF

# If publish IP is set and not localhost, append it to alt_names
if [ -n "$PUBLISH_IP" ] && [ "$PUBLISH_IP" != "127.0.0.1" ] && [ "$PUBLISH_IP" != "::1" ]; then
  echo "IP.2 = $PUBLISH_IP" >> "$CERT_DIR/openssl.cnf"
  echo "Including publish IP $PUBLISH_IP in certificate SANs"
fi

cat >> "$CERT_DIR/openssl.cnf" <<'EOF'
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

cd "$CERT_DIR"

echo "Generating new Elasticsearch HTTP CA and server certificate bundle..."
openssl genpkey -algorithm RSA -out http_ca.key -pkeyopt rsa_keygen_bits:4096
openssl req -x509 -new -nodes -key http_ca.key -sha256 -days 1095 -out http_ca.crt \
  -subj '/CN=Elasticsearch security auto-configuration HTTP CA' \
  -extensions v3_ca -config openssl.cnf
openssl genpkey -algorithm RSA -out http.key -pkeyopt rsa_keygen_bits:4096
openssl req -new -key http.key -out http.csr -config openssl.cnf
openssl x509 -req -in http.csr -CA http_ca.crt -CAkey http_ca.key -CAcreateserial \
  -out http.crt -days 825 -sha256 -extensions v3_req -extfile openssl.cnf
if [ -n "$HTTP_KEYSTORE_PASSWORD" ]; then
  openssl pkcs12 -export -out http.p12 -inkey http.key -in http.crt -certfile http_ca.crt -passout pass:"$HTTP_KEYSTORE_PASSWORD"
else
  openssl pkcs12 -export -out http.p12 -inkey http.key -in http.crt -certfile http_ca.crt -passout pass:
fi

cat <<'EOF'
Generation complete.
The new files are located in:
  $CERT_DIR/http_ca.crt
  $CERT_DIR/http.p12

To install them, run:
  sudo cp "$CERT_DIR/http.p12" /etc/elasticsearch/certs/http.p12
  sudo cp "$CERT_DIR/http_ca.crt" /etc/elasticsearch/certs/http_ca.crt
  sudo chown root:elasticsearch /etc/elasticsearch/certs/http.p12 /etc/elasticsearch/certs/http_ca.crt
  sudo chmod 640 /etc/elasticsearch/certs/http.p12
  sudo chmod 644 /etc/elasticsearch/certs/http_ca.crt
  sudo systemctl restart elasticsearch

Once the service restarts, set ELASTICSEARCH_VERIFY_CERTS=1 and optionally ELASTICSEARCH_ALLOW_INSECURE_FALLBACK=0.
EOF
