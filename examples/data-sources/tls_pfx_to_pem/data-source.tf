data "tls_pfx_to_pem" "this" {
  certificate_pfx = file("../../certificate.pfx")
  password_pfx    = ""
}
