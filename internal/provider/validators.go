// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/json"
	"encoding/pem"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// pemEncodedValidator ensures a string attribute is PEM-encoded. The
// block type is not inspected — algorithm-specific parsing happens
// later during signing.
type pemEncodedValidator struct{}

func (v pemEncodedValidator) Description(_ context.Context) string {
	return "value must be PEM-encoded"
}

func (v pemEncodedValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v pemEncodedValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	block, _ := pem.Decode([]byte(req.ConfigValue.ValueString()))
	if block == nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid PEM",
			"The value must be PEM-encoded.",
		)
	}
}

// jsonObjectValidator ensures a string attribute parses as a JSON
// object. JWT claim sets are always objects per RFC 7519 §4, so we
// reject arrays and scalars to fail loudly during plan instead of
// silently signing nonsense.
type jsonObjectValidator struct{}

func (v jsonObjectValidator) Description(_ context.Context) string {
	return "value must be a JSON object"
}

func (v jsonObjectValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v jsonObjectValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(req.ConfigValue.ValueString()), &obj); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid JSON",
			"The value must be a JSON object: "+err.Error(),
		)
	}
}
