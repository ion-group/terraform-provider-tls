package provider

import (
	"os"
	"strings"
	"testing"

	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	tu "github.com/hashicorp/terraform-provider-tls/internal/provider/testutils"
)

func TestDataSourcePfxToPem_CertificateContent(t *testing.T) {
	// Load the expected certificate and private key content from fixtures
	certPemContent, err := os.ReadFile("fixtures/certificate_pfx.pem")
	if err != nil {
		t.Fatalf("Failed to load certificate fixture: %v", err)
	}

	privateKeyContent, err := os.ReadFile("fixtures/private_key_pfx.pem")
	if err != nil {
		t.Fatalf("Failed to load private key fixture: %v", err)
	}

	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),

		Steps: []r.TestStep{
			{
				Config: `
					data "tls_pfx_to_pem" "test" {
						content_base64 = filebase64("fixtures/certificate.pfx")
						password    = ""
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					// Check that the certificate and private key were parsed correctly
					r.TestCheckResourceAttr(
						"data.tls_pfx_to_pem.test",
						"certificate_pem",
						strings.TrimSpace(string(certPemContent))+"\n"),
					r.TestCheckResourceAttr(
						"data.tls_pfx_to_pem.test",
						"private_key_pem",
						strings.TrimSpace(string(privateKeyContent))+"\n"),

					// Verify that the certificate is correctly formatted as PEM
					tu.TestCheckPEMFormat("data.tls_pfx_to_pem.test", "certificate_pem", PreambleCertificate.String()),

					// Verify that the private key is correctly formatted as PEM
					tu.TestCheckPEMFormat("data.tls_pfx_to_pem.test", "private_key_pem", PreamblePrivateKeyRSA.String()),
				),
			},
		},
	})
}
