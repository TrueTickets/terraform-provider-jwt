// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
)

// decodedTokenDataSource decodes a JWT into its constituent parts so
// downstream resources can reference individual claims. The full
// implementation is added in a follow-up commit.
type decodedTokenDataSource struct{}

var _ datasource.DataSource = (*decodedTokenDataSource)(nil)

// NewDecodedTokenDataSource is the constructor referenced by the provider.
func NewDecodedTokenDataSource() datasource.DataSource {
	return &decodedTokenDataSource{}
}

func (d *decodedTokenDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_decoded_token"
}

func (d *decodedTokenDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, _ *datasource.SchemaResponse) {
}

func (d *decodedTokenDataSource) Read(_ context.Context, _ datasource.ReadRequest, _ *datasource.ReadResponse) {
}
