#!/bin/sh

openssl genrsa -out ca-key.pem 2048
openssl req -new -x509 -days 3650 -key ca-key.pem -out ca-cert.pem -subj "/CN=proxy3 CA"
openssl genrsa -out ca-cert-key.pem 2048
mkdir certs/
