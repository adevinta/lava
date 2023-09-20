#!/bin/bash
# Copyright 2023 Adevinta

# generate_certs.sh generates a set of server and client certificates
# to use in Docker tests. These certificates have an expiration of 100
# years.

set -e -u

if [[ $# != 1 ]]; then
	echo 'usage: generate_certs.bash dir' >&2
	exit 2
fi

outdir=$1

if [[ -e $outdir ]]; then
	echo "error: ${outdir} already exists" >&2
	exit 1
fi

mkdir -p "${outdir}"
pushd "${outdir}"

openssl genrsa -out ca-key.pem 4096
openssl req -new -x509 -days 36500 -key ca-key.pem -sha256 -out ca.pem
openssl genrsa -out server-key.pem 4096
openssl req -subj "/CN=server" -sha256 -new -key server-key.pem -out server.csr
echo 'subjectAltName = IP:127.0.0.1' > extfile.cnf
echo 'extendedKeyUsage = serverAuth' >> extfile.cnf
openssl x509 -req -days 36499 -sha256 -in server.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out server-cert.pem -extfile extfile.cnf
openssl genrsa -out key.pem 4096
openssl req -subj '/CN=client' -new -key key.pem -out client.csr
echo 'extendedKeyUsage = clientAuth' > extfile-client.cnf
openssl x509 -req -days 36498 -sha256 -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out cert.pem -extfile extfile-client.cnf

popd
