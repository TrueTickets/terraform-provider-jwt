// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure jwtProvider satisfies provider interfaces.
var _ provider.Provider = (*jwtProvider)(nil)

// New returns a constructor suitable for providerserver.Serve, with the
// goreleaser-injected version stamped on the provider.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &jwtProvider{version: version}
	}
}

// jwtProvider implements the JWT terraform provider.
//
// The provider takes no configuration: token signing happens locally at
// apply time, and the inputs (algorithm, key/secret, claims) are supplied
// per-resource. The version field is populated by goreleaser via ldflags
// and surfaced through GetMetadata for diagnostics.
type jwtProvider struct {
	version string
}

func (p *jwtProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "jwt"
	resp.Version = p.version
}

func (p *jwtProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Generate JSON Web Tokens (JWTs) directly inside " +
			"Terraform/OpenTofu configuration. The provider has no " +
			"configuration: declare it and use the jwt_signed_token or " +
			"jwt_hashed_token resources, or the jwt_decoded_token data " +
			"source.",
	}
}

func (p *jwtProvider) Configure(_ context.Context, _ provider.ConfigureRequest, _ *provider.ConfigureResponse) {
}

func (p *jwtProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewSignedTokenResource,
		NewHashedTokenResource,
	}
}

func (p *jwtProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewDecodedTokenDataSource,
	}
}
