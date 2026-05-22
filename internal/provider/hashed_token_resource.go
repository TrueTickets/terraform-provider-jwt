// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// hashedTokenResource is the framework-port of jwt_hashed_token. The
// full implementation is added in a follow-up commit.
type hashedTokenResource struct{}

var _ resource.Resource = (*hashedTokenResource)(nil)

// NewHashedTokenResource is the constructor referenced by the provider.
func NewHashedTokenResource() resource.Resource {
	return &hashedTokenResource{}
}

func (r *hashedTokenResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_hashed_token"
}

func (r *hashedTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, _ *resource.SchemaResponse) {
}

func (r *hashedTokenResource) Create(_ context.Context, _ resource.CreateRequest, _ *resource.CreateResponse) {
}

func (r *hashedTokenResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
}

func (r *hashedTokenResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
}

func (r *hashedTokenResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}
