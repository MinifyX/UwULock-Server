#!/usr/bin/env bash
# A test CA and a certificate for localhost signed by it, for the end-to-end tests: Bitwarden's
# CLI only talks HTTPS, and WebAuthn only works on a site the browser trusts.
#
#   scripts/e2e/test-ca.sh <directory>
#
# Writes ca.pem, cert.pem and key.pem there, and prints the SHA-256 of the certificate's public
# key, for Chromium's --ignore-certificate-errors-spki-list.
set -euo pipefail

tls=$1
mkdir -p "$tls"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -subj "/CN=UwULock test CA" -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign -keyout "$tls/ca.key" -out "$tls/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=localhost \
  -keyout "$tls/key.pem" -out "$tls/leaf.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n' > "$tls/ext"
openssl x509 -req -in "$tls/leaf.csr" -CA "$tls/ca.pem" -CAkey "$tls/ca.key" -CAcreateserial \
  -days 1 -extfile "$tls/ext" -out "$tls/cert.pem" 2>/dev/null
# Readable for a server in a container, too.
chmod 644 "$tls/key.pem"
openssl x509 -in "$tls/cert.pem" -pubkey -noout | openssl pkey -pubin -outform der |
  openssl dgst -sha256 -binary | base64
