#!/usr/bin/env bash
set -euo pipefail

[[ $# -eq 1 ]] || {
  echo "usage: $0 <route-grant-public-key.pem>" >&2
  exit 2
}
key_file=$1
[[ -f $key_file ]] || {
  echo "Route Grant public key is not a regular file: $key_file" >&2
  exit 1
}
command -v openssl >/dev/null 2>&1 || {
  echo "openssl is required to validate the Route Grant public key" >&2
  exit 1
}
# OpenSSL can derive a public key even when `-pubin` is accidentally given a
# PKCS#8 private PEM. The worker must never accept or install private material.
grep -q '^-----BEGIN PUBLIC KEY-----$' "$key_file" \
  && grep -q '^-----END PUBLIC KEY-----$' "$key_file" \
  && ! grep -q 'PRIVATE KEY' "$key_file" || {
    echo "Route Grant verifier input must contain only a PEM public key" >&2
    exit 1
  }
openssl pkey -pubin -in "$key_file" -text_pub -noout \
  | grep -q '^ED25519 Public-Key:' || {
    echo "Route Grant key must be an Ed25519 public key" >&2
    exit 1
  }
openssl pkey -pubin -in "$key_file" -outform DER >/dev/null
