#!/bin/bash

# create root ca
base_dir="/home/ltong/self-signed-cert"
mkdir $base_dir/ca
mkdir $base_dir/ca/certs $base_dir/ca/crl $base_dir/ca/newcerts $base_dir/ca/private $base_dir/ca/csr $base_dir/ca/jks
chmod 700 $base_dir/ca/private
touch $base_dir/ca/index.txt
echo 1000 > $base_dir/ca/serial
touch $base_dir/ca/crlnumber

cat > ca/openssl.cnf << EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = `echo $base_dir`/ca
certs = \$dir/certs
crl_dir = \$dir/crl
new_certs_dir     = \$dir/newcerts
database          = \$dir/index.txt
serial            = \$dir/serial
RANDFILE          = \$dir/private/.rand

# The root key and root certificate.
private_key       = \$dir/private/ca.key.pem
certificate       = \$dir/certs/ca.cert.pem

# For certificate revocation lists.
crlnumber         = \$dir/crlnumber
crl               = \$dir/crl/ca.crl.pem
crl_extensions    = crl_ext
default_crl_days  = 30

# SHA-1 is deprecated, so use SHA-2 instead.
default_md        = sha256

name_opt          = ca_default
cert_opt          = ca_default
default_days      = 375
preserve          = no
policy            = policy_strict

[ policy_strict ]
# The root CA should only sign intermediate certificates that match.
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
# Allow the intermediate CA to sign a more diverse range of certificates.
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
# Options for the req tool.
default_bits        = 2048
distinguished_name  = req_distinguished_name
string_mask         = utf8only
#req_extensions     = req_ext

[ req_ext ]
subjectAltName = @alt_names

[alt_names]
DNS.1   = localhost
#DNS.2   = *.something.com

# SHA-1 is deprecated, so use SHA-2 instead.
default_md          = sha256

# Extension to add when the -x509 option is used.
x509_extensions     = v3_ca

[ req_distinguished_name ]
# See <https://en.wikipedia.org/wiki/Certificate_signing_request>.
countryName                     = Country Name (2 letter code)
stateOrProvinceName             = State or Province Name
localityName                    = Locality Name
0.organizationName              = Organization Name
organizationalUnitName          = Organizational Unit Name
commonName                      = Common Name
emailAddress                    = Email Address

# Optionally, specify some defaults.
countryName_default             = US
stateOrProvinceName_default     = MD
localityName_default            = 
0.organizationName_default      = 
organizationalUnitName_default  = 
#emailAddress_default           =

[ v3_ca ]
# Extensions for a typical CA.
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_intermediate_ca ]
# Extensions for a typical intermediate CA.
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
# Extensions for client certificates.
basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = "OpenSSL Generated Client Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection

[ server_cert ]
# Extensions for server certificates.
basicConstraints = CA:FALSE
nsCertType = server
nsComment = "OpenSSL Generated Server Certificate"
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
crlDistributionPoints = URI:http://localhost/ca.crl.pem

[ crl_ext ]
# Extension for CRLs.
authorityKeyIdentifier=keyid:always

[ ocsp ]
# Extension for OCSP signing certificates.
basicConstraints = CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, OCSPSigning
EOF

cd $base_dir/ca
echo "Creating CA"
openssl genrsa -aes256 -out private/ca.key.pem 4096

chmod 400 private/ca.key.pem

openssl req -config openssl.cnf \
      -key private/ca.key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -out certs/ca.cert.pem

chmod 444 certs/ca.cert.pem

echo "Creating localhost"
openssl genrsa -aes256 -out private/localhost.key.pem 2048
chmod 400 private/localhost.key.pem

echo "replace openssl.cnf for SAN"

sed -i 's/#req_extensions/req_extensions/g' openssl.cnf

openssl req -config openssl.cnf \
      -key private/localhost.key.pem \
      -new -sha256 -out csr/localhost.csr.pem

openssl ca -config openssl.cnf \
      -extensions server_cert -days 375 -notext -md sha256 \
      -in csr/localhost.csr.pem \
      -out certs/localhost.cert.pem

chmod 444 certs/localhost.cert.pem

echo "Creating CRL"
openssl ca -config openssl.cnf -gencrl -out crl/ca.crl.pem

sed -i 's/req_extensions/#req_extensions/g' openssl.cnf

echo "Creating client1"
openssl genrsa -out private/client1.key.pem 2048
openssl req -new -key private/client1.key.pem -out csr/client1.csr.pem

echo "signing client cert now"
openssl ca -config openssl.cnf \
      -extensions usr_cert -notext -md sha256 \
      -in csr/client1.csr.pem \
      -out certs/client1.cert.pem

openssl verify -CAfile certs/ca.cert.pem certs/client1.cert.pem

echo "Generating keystore"
openssl pkcs12 -export -in certs/localhost.cert.pem -inkey private/localhost.key.pem \
               -out localhost.p12 -name localhost \
               -CAfile certs/ca.cert.pem -caname root

keytool -importkeystore \
        -deststorepass changeit -destkeypass changeit -destkeystore localhost.jks \
        -srckeystore localhost.p12 -srcstoretype PKCS12 -srcstorepass changeit \
        -alias localhost

keytool -importcert -keystore localhost.jks -file certs/ca.cert.pem -alias iEdisonRoot

echo "create client p12"
openssl pkcs12 -export -in certs/client1.cert.pem -inkey private/client1.key.pem \
               -out client1.p12 -name client1 \
               -CAfile certs/ca.cert.pem -caname root
