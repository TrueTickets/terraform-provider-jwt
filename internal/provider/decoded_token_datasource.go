// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	jwtgen "github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// decodedTokenDataSource decodes a compact-serialized JWT into its
// header, claims, and signature. No signature verification is performed;
// the data source is purely a parser so downstream resources can read
// individual claim values out of a token that was produced elsewhere
// (for example, a token received from an external service).
type decodedTokenDataSource struct{}

var _ datasource.DataSource = (*decodedTokenDataSource)(nil)

// NewDecodedTokenDataSource is the constructor referenced by the provider.
func NewDecodedTokenDataSource() datasource.DataSource {
	return &decodedTokenDataSource{}
}

type decodedTokenDataSourceModel struct {
	Token        types.String `tfsdk:"token"`
	HeaderJSON   types.String `tfsdk:"header_json"`
	ClaimsJSON   types.String `tfsdk:"claims_json"`
	SignatureB64 types.String `tfsdk:"signature_b64"`
	Algorithm    types.String `tfsdk:"algorithm"`
}

func (d *decodedTokenDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_decoded_token"
}

func (d *decodedTokenDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Decodes a compact-serialized JWT into its header, " +
			"claims, and signature. The signature is **not** verified: " +
			"use this data source to read claims out of a token whose " +
			"trust is already established by other means (TLS, mTLS, " +
			"key-rotated upstream service).",
		Attributes: map[string]schema.Attribute{
			"token": schema.StringAttribute{
				Description: "The compact-serialized JWT to decode.",
				Required:    true,
				Sensitive:   true,
			},
			"header_json": schema.StringAttribute{
				Description: "JSON-encoded JWT header (JOSE header).",
				Computed:    true,
			},
			"claims_json": schema.StringAttribute{
				Description: "JSON-encoded JWT claims payload.",
				Computed:    true,
			},
			"signature_b64": schema.StringAttribute{
				Description: "Base64url-encoded JWT signature (third segment).",
				Computed:    true,
			},
			"algorithm": schema.StringAttribute{
				Description: "Signing algorithm declared in the header `alg` claim.",
				Computed:    true,
			},
		},
	}
}

func (d *decodedTokenDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config decodedTokenDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	header, claims, signature, alg, err := decodeJWT(config.Token.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to decode JWT", err.Error())
		return
	}

	config.HeaderJSON = types.StringValue(header)
	config.ClaimsJSON = types.StringValue(claims)
	config.SignatureB64 = types.StringValue(signature)
	config.Algorithm = types.StringValue(alg)

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// decodeJWT splits the compact serialization, parses the header and
// claims as JSON, and returns canonical JSON strings plus the raw
// signature segment.
func decodeJWT(token string) (header, claims, signature, alg string, err error) {
	if strings.TrimSpace(token) == "" {
		return "", "", "", "", fmt.Errorf("token is empty")
	}

	parser := jwtgen.NewParser()
	parsed, parts, err := parser.ParseUnverified(token, jwtgen.MapClaims{})
	if err != nil {
		return "", "", "", "", fmt.Errorf("parsing token: %w", err)
	}
	if len(parts) != 3 {
		return "", "", "", "", fmt.Errorf("token does not have three compact-serialized segments")
	}

	headerBytes, err := json.Marshal(parsed.Header)
	if err != nil {
		return "", "", "", "", fmt.Errorf("re-encoding header: %w", err)
	}
	claimsBytes, err := json.Marshal(parsed.Claims)
	if err != nil {
		return "", "", "", "", fmt.Errorf("re-encoding claims: %w", err)
	}

	if v, ok := parsed.Header["alg"].(string); ok {
		alg = v
	}

	return string(headerBytes), string(claimsBytes), parts[2], alg, nil
}
