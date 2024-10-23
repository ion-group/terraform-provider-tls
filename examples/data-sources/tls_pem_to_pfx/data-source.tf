data "tls_pem_to_pfx" "this" {
  password_pfx    = ""
  certificate_pem = file("../../certificate.pem")
  private_key_pem = file("../../private_key.pem")
}