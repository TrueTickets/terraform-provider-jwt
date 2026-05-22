// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// TestPEMEncodedValidator exercises both the accept- and reject-paths
// without going through the Terraform lifecycle, so the validator can
// be evolved without rerunning the full acceptance suite.
func TestPEMEncodedValidator(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantError bool
	}{
		{
			name:      "valid rsa pem",
			input:     "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n",
			wantError: false,
		},
		{
			name:      "missing pem markers",
			input:     "MIIB",
			wantError: true,
		},
		{
			name:      "empty string",
			input:     "",
			wantError: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validator.StringRequest{
				Path:        path.Root("key"),
				ConfigValue: types.StringValue(tc.input),
			}
			var resp validator.StringResponse
			pemEncodedValidator{}.ValidateString(context.Background(), req, &resp)
			if got := resp.Diagnostics.HasError(); got != tc.wantError {
				t.Fatalf("wantError=%v, got diagnostics=%v", tc.wantError, resp.Diagnostics)
			}
		})
	}
}

// TestJSONObjectValidator ensures only well-formed JSON objects pass.
// Arrays and scalars must be rejected — JWT claims are objects per
// RFC 7519 §4.
func TestJSONObjectValidator(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		wantError bool
	}{
		{"valid empty object", `{}`, false},
		{"valid populated object", `{"sub":"alice","exp":1234567890}`, false},
		{"valid object null", `null`, false}, // json.Unmarshal accepts null into map (leaves it nil)
		{"array rejected", `["a","b"]`, true},
		{"scalar rejected", `"a string"`, true},
		{"number rejected", `42`, true},
		{"malformed json", `{`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := validator.StringRequest{
				Path:        path.Root("claims_json"),
				ConfigValue: types.StringValue(tc.input),
			}
			var resp validator.StringResponse
			jsonObjectValidator{}.ValidateString(context.Background(), req, &resp)
			if got := resp.Diagnostics.HasError(); got != tc.wantError {
				t.Fatalf("wantError=%v, got diagnostics=%v", tc.wantError, resp.Diagnostics)
			}
		})
	}
}

// TestPEMEncodedValidator_unknownAndNullSkip confirms the validator
// short-circuits on null/unknown — required for use in
// computed-by-default chains.
func TestPEMEncodedValidator_unknownAndNullSkip(t *testing.T) {
	for _, val := range []types.String{types.StringNull(), types.StringUnknown()} {
		req := validator.StringRequest{Path: path.Root("key"), ConfigValue: val}
		var resp validator.StringResponse
		pemEncodedValidator{}.ValidateString(context.Background(), req, &resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("null/unknown should not produce diagnostics: %v", resp.Diagnostics)
		}
	}
}
