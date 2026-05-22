// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccDecodedTokenDataSource_decodeFixedToken feeds the data source
// a known HS512 token and asserts each decoded field. The token is the
// same fixture used by TestAccHashedTokenResource_lifecycle, so the two
// tests cross-check each other: if either changes its output, this
// fails.
//
//	header  = {"alg":"HS512","typ":"JWT"}
//	payload = {"a":"b"}
func TestAccDecodedTokenDataSource_decodeFixedToken(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "jwt_decoded_token" "example" {
  token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.cl5DXDjjNUqWzYcsSOvljSs9skgxV7xrxXr6IFXdN_FEYe7qOw-IsWBQBAyB1Ra3kfngwT9h2VK1YuT00Qp-rg"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.jwt_decoded_token.example", "algorithm", "HS512"),
					resource.TestCheckResourceAttr("data.jwt_decoded_token.example", "header_json", `{"alg":"HS512","typ":"JWT"}`),
					resource.TestCheckResourceAttr("data.jwt_decoded_token.example", "claims_json", `{"a":"b"}`),
					resource.TestCheckResourceAttr(
						"data.jwt_decoded_token.example",
						"signature_b64",
						"cl5DXDjjNUqWzYcsSOvljSs9skgxV7xrxXr6IFXdN_FEYe7qOw-IsWBQBAyB1Ra3kfngwT9h2VK1YuT00Qp-rg",
					),
				),
			},
		},
	})
}

// TestAccDecodedTokenDataSource_pipelineFromResource is the canonical
// integration test: it signs a token via jwt_hashed_token, then feeds
// the resource's output into the data source in the same config. This
// proves the resource → data-source pipeline works end-to-end and
// guards against schema-shape mismatches between the producer and the
// consumer.
func TestAccDecodedTokenDataSource_pipelineFromResource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "jwt_hashed_token" "produced" {
  algorithm   = "HS256"
  secret      = "test-secret"
  claims_json = jsonencode({ iss = "test-issuer", sub = "user-1" })
}

data "jwt_decoded_token" "decoded" {
  token = jwt_hashed_token.produced.token
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.jwt_decoded_token.decoded", "algorithm", "HS256"),
					resource.TestCheckResourceAttr(
						"data.jwt_decoded_token.decoded",
						"claims_json",
						`{"iss":"test-issuer","sub":"user-1"}`,
					),
					// Cross-reference: the data source's claims_json
					// must round-trip the resource's claims_json.
					resource.TestCheckResourceAttrPair(
						"data.jwt_decoded_token.decoded", "claims_json",
						"jwt_hashed_token.produced", "claims_json",
					),
				),
			},
		},
	})
}

// TestAccDecodedTokenDataSource_invalidToken exercises the parser's
// error path.
func TestAccDecodedTokenDataSource_invalidToken(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
data "jwt_decoded_token" "example" {
  token = "not.a.jwt"
}
`,
				ExpectError: regexpMatch(`Failed to decode JWT`),
			},
		},
	})
}
