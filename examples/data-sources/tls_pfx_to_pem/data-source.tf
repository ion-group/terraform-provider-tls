terraform {

  # https://github.com/hashicorp/terraform/releases
  required_version = ">= 1.1.7"

  required_providers {
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0.0"
    }
  }
}


data "tls_pfx_to_pem" "this" {
  content_base64 = filebase64("../../../internal/provider/fixtures/certificate.pfx")
  # content_base64 = filebase64("output.pfx")
  password    = ""
}

# output "certificate_pem" {
#   # sensitive = true
#   value = data.tls_pfx_to_pem.this.certificate_pem
# }

# output "private_key_pem" {
#   # sensitive = true
#   value = nonsensitive(data.tls_pfx_to_pem.this.private_key_pem)
# }

resource "local_sensitive_file" "certificate_pem" {
  filename = "${path.module}/certificate.pem"
  content  = data.tls_pfx_to_pem.this.certificate_pem
}

resource "local_sensitive_file" "private_key" {
  filename = "${path.module}/private_key.pem"
  content  = data.tls_pfx_to_pem.this.private_key_pem
}

