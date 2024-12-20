

# Note
# Pem files are generated in PKCS#8 format as it's generalized format for private keys that supports all algorithm types
# It supports multiple algorithm types as below
# RSA
# DSA
# ECDSA
# Elliptic Curve keys
# EdDSA
# PKCS#8 format includes a field to specify the algorithm used for encryption which makes it algorithm agnostic
# PKCS#1 is a legacy key format in the context of modern cryptographic practices specifically designed for limited set of algorithm types

locals {
  pfx_file_path = "../../../internal/provider/fixtures/certificate_rsa_legacy.pfx"
}

data "tls_pfx_to_pem" "this" {
  content_base64 = filebase64(local.pfx_file_path)
  password       = ""
}

resource "local_sensitive_file" "certificate_pem" {
  filename = "${path.module}/certificate.pem"
  content  = data.tls_pfx_to_pem.this.certificate_pem
}

resource "local_sensitive_file" "private_key" {
  filename = "${path.module}/private_key.pem"
  content  = data.tls_pfx_to_pem.this.private_key_pem
}

