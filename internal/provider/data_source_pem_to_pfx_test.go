package provider

import (
	"encoding/base64"
	"os"
	"testing"

	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	// For Terraform state access
)

func TestDataSourcePemToPfx_CertificateContent(t *testing.T) {
	// Load the expected certificate and private key content from fixtures
	certPfxBinary, err := os.ReadFile("fixtures/certificate.pfx")
	if err != nil {
		t.Fatalf("Failed to load certificate fixture: %v", err)
	}

	// Encode the content to Base64
	certPfxBase64 := base64.StdEncoding.EncodeToString(certPfxBinary)

	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),

		Steps: []r.TestStep{
			{
				Config: `
					data "tls_pem_to_pfx" "test" {
						password_pfx    = ""
						certificate_pem = file("fixtures/certificate_pfx.pem")
						private_key_pem = file("fixtures/private_key_pfx.pem")
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					// Check that the certificate and private key were parsed correctly
					r.TestCheckResourceAttr(
						"data.tls_pem_to_pfx.test",
						"certificate_pfx",
						certPfxBase64),

					// // Verify that the certificate is correctly formatted as PEM
					// tu.TestCheckPEMFormat("data.tls_pfx_to_pem.test", "certificate_pem", PreambleCertificate.String()),

					// // Verify that the private key is correctly formatted as PEM
					// tu.TestCheckPEMFormat("data.tls_pfx_to_pem.test", "private_key_pem", PreamblePrivateKeyPKCS8.String()),
				),
			},
		},
	})
}

// func TestDataSourcePemToPfx_CertificateContent(t *testing.T) {
// 	// Load the expected certificate and private key content from fixtures
// 	expectedPfxBinary, err := os.ReadFile("fixtures/certificate.pfx")
// 	if err != nil {
// 		t.Fatalf("Failed to load certificate fixture: %v", err)
// 	}

// 	// Encode the content to Base64
// 	expectedPfxBase64 := base64.StdEncoding.EncodeToString(expectedPfxBinary)

// 	r.UnitTest(t, r.TestCase{
// 		ProtoV5ProviderFactories: protoV5ProviderFactories(),

// 		Steps: []r.TestStep{
// 			{
// 				Config: `
// 					data "tls_pem_to_pfx" "test" {
// 						password_pfx    = ""
// 						certificate_pem = file("fixtures/certificate_pfx.pem")
// 						private_key_pem = file("fixtures/private_key_pfx.pem")
// 					}
// 				`,
// 				Check: r.ComposeAggregateTestCheckFunc(
// 					// Verify the generated PFX matches the expected PFX (Base64 comparison)
// 					func(s *terraform.State) error {
// 						// Retrieve the generated PFX from the state
// 						resourceState := s.RootModule().Resources["data.tls_pem_to_pfx.test"]
// 						if resourceState == nil {
// 							return fmt.Errorf("resource not found")
// 						}

// 						generatedPfxBase64 := strings.TrimSpace(resourceState.Primary.Attributes["certificate_pfx"])
// 						if generatedPfxBase64 != expectedPfxBase64 {
// 							return fmt.Errorf("mismatch in PFX content:\nExpected: %s\nGenerated: %s",
// 								expectedPfxBase64, generatedPfxBase64)
// 						}
// 						return nil
// 					},
// 				),
// 			},
// 		},
// 	})
// }
