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


data "tls_pem_to_pfx" "this" {
  password_pfx    = ""
  certificate_pem = file("../../../internal/provider/fixtures/certificate_pfx.pem")
  private_key_pem = file("../../../internal/provider/fixtures/private_key_pfx.pem")
  # certificate_pem = file("certificate.pfx.pem")
  # private_key_pem = file("private_key.pem")
}

resource "local_sensitive_file" "example" {
  filename = "${path.module}/output.pfx"
  content_base64  = data.tls_pem_to_pfx.this.certificate_pfx
}
