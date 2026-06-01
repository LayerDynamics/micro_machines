#!/usr/bin/env bash
# Generate a development mTLS CA plus a controller (server) and agent (client)
# certificate for the MicroMachines control plane (SPEC-1 FR-19).
#
# Output (default ./certs): ca.pem, server.pem/server.key, client.pem/client.key.
# The controller loads ca.pem + server.pem/key and requires a client cert; the agent
# loads ca.pem + client.pem/key. The server cert's SAN is the controller hostname the
# agent connects to (default "localhost"; override with CONTROLLER_DNS).
#
# This is for local/dev use. The reconcile-loop integration test mints its own
# equivalent certs in-process (via rcgen) so it needs no external files.
set -euo pipefail

OUT="${1:-./certs}"
CONTROLLER_DNS="${CONTROLLER_DNS:-localhost}"
DAYS="${DAYS:-825}"

mkdir -p "$OUT"
cd "$OUT"

echo "generating dev mTLS certs in $(pwd) (controller DNS=${CONTROLLER_DNS})"

# 1. CA.
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
  -subj "/CN=MicroMachines Dev CA" -out ca.pem 2>/dev/null

# 2. Controller (server) cert with a SAN matching the dialed hostname.
openssl genrsa -out server.key 2048 2>/dev/null
openssl req -new -key server.key -subj "/CN=${CONTROLLER_DNS}" -out server.csr 2>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days "$DAYS" -sha256 -out server.pem \
  -extfile <(printf "subjectAltName=DNS:%s,IP:127.0.0.1\nextendedKeyUsage=serverAuth" "$CONTROLLER_DNS") 2>/dev/null

# 3. Agent (client) cert.
openssl genrsa -out client.key 2048 2>/dev/null
openssl req -new -key client.key -subj "/CN=mm-agent" -out client.csr 2>/dev/null
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days "$DAYS" -sha256 -out client.pem \
  -extfile <(printf "extendedKeyUsage=clientAuth") 2>/dev/null

rm -f server.csr client.csr ca.srl
chmod 600 ./*.key
echo "wrote: ca.pem server.pem server.key client.pem client.key"
