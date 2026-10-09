#!/bin/sh
# Local example credentials only. Requires OpenSSL 3.
set -eu
umask 077
keychain_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT HUP INT TERM
cd "$work_dir"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
openssl req -new -x509 -key ca.key -sha256 -days 3650 \
    -subj '/CN=dquic echo example CA' -out ca.pem \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign,digitalSignature'
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out server.key
openssl req -new -key server.key -subj '/CN=localhost' -out server.csr

touch index.txt
printf '01\n' > serial
cat > ca.cnf <<'EOF'
[ca]
default_ca = local_ca
[local_ca]
database = index.txt
new_certs_dir = .
certificate = ca.pem
private_key = ca.key
serial = serial
default_md = sha256
default_days = 3650
policy = names
x509_extensions = server
[names]
commonName = supplied
[server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
openssl ca -batch -config ca.cnf -in server.csr -out server.pem -notext
openssl ocsp -index index.txt -CA ca.pem -rsigner ca.pem -rkey ca.key \
    -issuer ca.pem -cert server.pem -respout server.ocsp -ndays 3650 -no_nonce
openssl verify -CAfile ca.pem -verify_hostname localhost -purpose sslserver server.pem
openssl ocsp -respin server.ocsp -issuer ca.pem -cert server.pem -CAfile ca.pem -no_nonce

openssl x509 -in ca.pem -outform DER -out "$keychain_dir/ca.der"
openssl x509 -in server.pem -outform DER -out "$keychain_dir/server.der"
openssl pkcs8 -topk8 -nocrypt -in server.key -outform DER -out "$keychain_dir/server.key.der"
cp server.ocsp "$keychain_dir/server.ocsp"
printf 'Generated example CA, server certificate, private key and OCSP in %s\n' "$keychain_dir"
