// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// signedTokenResource is the framework-port of jwt_signed_token.
//
// This file currently contains only the constructor and interface
// assertions. The full schema, CRUD handlers, and validators land in a
// follow-up commit; defining the symbol now keeps provider.go compilable
// while the migration is in flight.
type signedTokenResource struct{}

var _ resource.Resource = (*signedTokenResource)(nil)

// NewSignedTokenResource is the constructor referenced by the provider.
func NewSignedTokenResource() resource.Resource {
	return &signedTokenResource{}
}

func (r *signedTokenResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_signed_token"
}

func (r *signedTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, _ *resource.SchemaResponse) {
}

func (r *signedTokenResource) Create(_ context.Context, _ resource.CreateRequest, _ *resource.CreateResponse) {
}

func (r *signedTokenResource) Read(_ context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
}

func (r *signedTokenResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
}

func (r *signedTokenResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}
