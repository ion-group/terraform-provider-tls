// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto"

	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"software.sslmate.com/src/go-pkcs12"
)

// Define the PFX data source struct
type pemDataSource struct {
	provider *tlsProvider
}

var _ datasource.DataSource = (*pemDataSource)(nil)

// New PFX Data Source
func NewPemToPfxDataSource() datasource.DataSource {
	return &pemDataSource{}
}

// Metadata for the PFX Data Source
func (d *pemDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pem_to_pfx"
}

// Configure method for the PEM Data Source
func (d *pemDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.provider, resp.Diagnostics = toProvider(req.ProviderData)
}

func (d *pemDataSource) Schema(_ context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"certificate_pem": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "Certificate or certificate chain",
			},
			"private_key_pem": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "Private Key",
			},
			"password_pem": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Computed:  true,
				// Default:     stringdefault.StaticString(""),
				Description: "Private Key password",
			},
			"password_pfx": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "Keystore password",
			},
			"encoding_pfx": schema.StringAttribute{
				Optional: true,
				Computed: true,
				// Default:     stringdefault.StaticString("modern2023"),
				Description: "Set encoding for pfx certificate ",
			},
			"certificate_pfx": schema.StringAttribute{
				Computed:    true,
				Description: "Generated PFX data base64 encoded",
			},
		},
		MarkdownDescription: "Converts a PEM certificate and private key into a PFX file using the provided password.",
	}
}

// Read fetches the certificates either from a URL or from provided content and populates the state.
func (ds *pemDataSource) Read(ctx context.Context, req datasource.ReadRequest, res *datasource.ReadResponse) {
	tflog.Debug(ctx, "Creating PEM to PFX resource")

	// Load entire configuration into the model
	var newState PemToPfxDataSourceModel
	res.Diagnostics.Append(req.Config.Get(ctx, &newState)...)
	if res.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Loaded PEM to PFX configuration", map[string]interface{}{
		"pemToPfxConfig": fmt.Sprintf("%+v", newState),
	})

	encoder := pkcs12.Modern2023
	CertPem := newState.CertPem.ValueString()
	tflog.Debug(ctx, "Certificate PEM", map[string]interface{}{
		"cert_pem": []byte(CertPem),
	})

	// Decode certificate and CA certs
	certificate, caListAndIntermediate, err := decodeCerts([]byte(CertPem))
	if err != nil {
		res.Diagnostics.AddError("Failed to decode certificate PEM", err.Error())
		return
	}

	PrivateKeyPem := newState.PrivateKeyPem.ValueString()
	tflog.Debug(ctx, "Private Key PEM", map[string]interface{}{
		"private_key_pem": []byte(PrivateKeyPem),
	})

	//Decode private key
	privateKeys, err := decodePrivateKeysFromPem([]byte(PrivateKeyPem), []byte(newState.PrivateKeyPass.ValueString()))
	if err != nil || len(privateKeys) == 0 {
		res.Diagnostics.AddError("Failed to decode private key PEM", "No valid private key found")
		return
	}

	if len(privateKeys) != 1 {
		res.Diagnostics.AddError("private_key_pem must contain exactly one private key", "Check the Input")
		return
	}

	// Generate PFX data
	pfxData, err := encoder.Encode(privateKeys[0].(*rsa.PrivateKey), certificate, caListAndIntermediate, newState.PfxPassword.ValueString())
	if err != nil {
		res.Diagnostics.AddError("Failed to create PFX data", err.Error())
		return
	}

	// Set PFX data and ID in the new state
	newState.CertPfx = types.StringValue(base64.StdEncoding.EncodeToString(pfxData))

	// Set the final state
	tflog.Debug(ctx, "Storing PEM to PFX info into the state")
	res.Diagnostics.Append(res.State.Set(ctx, newState)...)
}

func decodeCerts(certStr []byte) (*x509.Certificate, []*x509.Certificate, error) {
	certificates, err := decodeCertificates(certStr)
	if err != nil {
		return nil, nil, fmt.Errorf("Error decoding certificates: %w", err)
	}
	if len(certificates) == 0 {
		return nil, nil, fmt.Errorf("cert_pem must contain at least one certificate")
	}
	return certificates[0], certificates[1:], nil
}

// decodeCertificate decodes a certificate from a PEM formated byte array.
// Given data must contain exactly one certificate.
func decodeCertificates(raw []byte) ([]*x509.Certificate, error) {
	certList, err := decodePemCertificates([]byte(raw))
	if err != nil {
		return nil, err
	}

	list := []*x509.Certificate{}
	for _, v := range certList {
		c, err := x509.ParseCertificate(v)
		if err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, nil
}

// decodePemCertificates decodes all certificates from a PEM formated byte array.
func decodePemCertificates(raw []byte) ([][]byte, error) {
	var certList [][]byte
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certList = append(certList, block.Bytes)
		}
		// ignore non-certificates
		raw = rest
	}
	return certList, nil
}

// decodePemCA decodes CA certificates from given PEM data
func decodePemCA(raw []byte) ([]*x509.Certificate, error) {
	var caList []*x509.Certificate
	var certList [][]byte
	certList, err := decodePemCertificates(raw)
	if err != nil {
		return caList, err
	}
	for _, c := range certList {
		c1, err := x509.ParseCertificate(c)
		if err != nil {
			return caList, err
		}
		caList = append(caList, c1)
	}
	return caList, nil
}

// decodePrivateKeysFromPem decodes a private keys from the given PEM formated byte array.
func decodePrivateKeysFromPem(raw, password []byte) ([]crypto.PrivateKey, error) {
	var keys []crypto.PrivateKey
	for {
		block, rest := pem.Decode(raw)
		if block == nil {
			break
		}

		blockRaw := block.Bytes
		if x509.IsEncryptedPEMBlock(block) {
			if len(password) == 0 {
				return keys, fmt.Errorf("cannot decrypt PEM Block. Please provide a password for the private key")
			}
			decrypted, err := x509.DecryptPEMBlock(block, password)
			if err != nil {
				return keys, fmt.Errorf("cannot decrypt PEM Block: %s", err)
			}
			blockRaw = decrypted
		}

		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(blockRaw)
			if err != nil {
				return keys, err
			}
			keys = append(keys, key)
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(blockRaw)
			if err != nil {
				return keys, nil
			}
			switch key := key.(type) {
			case *rsa.PrivateKey, *ecdsa.PrivateKey:
				keys = append(keys, key)
			default:
				return nil, fmt.Errorf("found unknown private key type in PKCS#8 wrapping")
			}
		case "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(blockRaw)
			if err != nil {
				return keys, nil
			}
			keys = append(keys, key)
		}
		raw = rest
	}

	return keys, nil
}
