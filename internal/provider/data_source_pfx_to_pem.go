// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"context"
	"encoding/pem"
	"io/ioutil"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/crypto/pkcs12"
)

// Define the PFX data source struct
type pfxDataSource struct {
	provider *tlsProvider
}

var _ datasource.DataSource = (*pfxDataSource)(nil)

// New PFX Data Source
func NewPfxToPemDataSource() datasource.DataSource {
	return &pfxDataSource{}
}

// Metadata for the PFX Data Source
func (d *pfxDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pfx_to_pem"
}

// Configure method for the PFX Data Source
func (d *pfxDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.provider, resp.Diagnostics = toProvider(req.ProviderData)
}

// Implement the Schema method
func (d *pfxDataSource) Schema(_ context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"certificate_pfx": schema.StringAttribute{
				Required: true,
				// MarkdownDescription: "Contents of PFX certificate in base64 encoded string",
				MarkdownDescription: "PFX certificate in binary format in a file",
			},
			"password_pfx": schema.StringAttribute{
				Required:            true,
				Sensitive:           true,
				MarkdownDescription: "Password for the PFX certificate",
			},
			"certificate_pem": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The certificate in pem format",
			},
			"private_key_pem": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "The private key in pem format",
			},
		},
		MarkdownDescription: "Convert pfx certificate to pem format.",
	}
}

// Read method for the PFX Data Source
func (d *pfxDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state PfxToPemDataSourceModel

	// Get the current state from the config
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	//Read the PFX file and extract data
	fileName := state.Certificate_pfx.ValueString()
	pfxData, err := ioutil.ReadFile(fileName)
	if err != nil {
		resp.Diagnostics.AddError("Failed to read PFX file", err.Error())
		return
	}

	// pfxData := []byte(state.Certificate_pfx.ValueString())
	pfxPassword := state.Password_pfx.ValueString()
	pemBlocks, err := pkcs12.ToPEM(pfxData, pfxPassword)
	if err != nil {
		resp.Diagnostics.AddError("Failed to decode PFX data", err.Error())
		return
	}

	// Process the PEM blocks for certificate and private key
	var (
		certificatePEM string
		privateKeyPEM  string
	)

	for _, pemBlock := range pemBlocks {
		switch pemBlock.Type {
		case "CERTIFICATE":
			if certificatePEM == "" {
				certificatePEM, err = pemToString(pemBlock)
				if err != nil {
					resp.Diagnostics.AddError("Failed to convert certificate to PEM", err.Error())
					return
				}
			}
		case "PRIVATE KEY":
			if privateKeyPEM == "" {
				privateKeyPEM, err = pemToString(pemBlock)
				if err != nil {
					resp.Diagnostics.AddError("Failed to convert private key to PEM", err.Error())
					return
				}
			}
		}
	}

	// Set the certificate and private key in the state
	state.Certificate_pem = types.StringValue(certificatePEM)
	state.Private_key_pem = types.StringValue(privateKeyPEM)

	// Set the final state
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Helper function to convert PEM block to string
func pemToString(pemBlock *pem.Block) (string, error) {

	// Remove any headers from the PEM block
	pemBlock.Headers = nil

	var buffer bytes.Buffer
	err := pem.Encode(&buffer, pemBlock)
	if err != nil {
		return "", err
	}

	return buffer.String(), nil
}
