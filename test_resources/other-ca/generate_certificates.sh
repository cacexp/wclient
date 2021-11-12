#!/bin/bash

rm *.crt *.key *.csr

# Generate the Root CA certificate
openssl req -nodes -x509 -days 3650 -newkey rsa:4096 -keyout ca.key -out ca.crt -sha256 -batch -subj "/CN=Other RSA CA"

# Create the Client Key and CSR - All of this is required for the client (the web browser client)
openssl req -nodes -newkey rsa:4096 -keyout client.key -out client.csr -sha256 -batch -subj "/CN=Other Client"


# Sign the client certificate with our CA cert.
openssl x509 -req -days 2000 -sha256 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 124 -out client.crt -extensions v3_end -extfile openssl.cnf

# Bundle the private key & cert for end-user client use
cat client.crt ca.crt > full_client.crt
