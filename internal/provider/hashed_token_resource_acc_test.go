// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

// TestAccHashedTokenResource_lifecycle exercises the full Terraform
// lifecycle for jwt_hashed_token: Create, Read with no drift,
// ImportStateVerify, and an in-place re-apply that must not produce a
// diff (proving UseStateForUnknown is wired up on the computed
// attributes). The byte-equal assertion on `token` is the regression
// guard against accidental output drift between releases.
func TestAccHashedTokenResource_lifecycle(t *testing.T) {
	const config = `
resource "jwt_hashed_token" "example" {
  algorithm   = "HS512"
  secret      = "notthegreatestkey"
  claims_json = jsonencode({ a = "b" })
}
`
	const expectedToken = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.cl5DXDjjNUqWzYcsSOvljSs9skgxV7xrxXr6IFXdN_FEYe7qOw-IsWBQBAyB1Ra3kfngwT9h2VK1YuT00Qp-rg"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create + Read.
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("jwt_hashed_token.example", "token", expectedToken),
					resource.TestCheckResourceAttr("jwt_hashed_token.example", "algorithm", "HS512"),
					resource.TestCheckResourceAttr("jwt_hashed_token.example", "secret_encoding", "raw"),
					resource.TestCheckResourceAttrSet("jwt_hashed_token.example", "id"),
				),
			},
			// Step 2: Re-apply identical config — must be a no-op.
			{
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
			},
			// Step 3: ImportStateVerify — round-trip the id and ensure
			// the imported state matches what we already have.
			{
				ResourceName:      "jwt_hashed_token.example",
				ImportState:       true,
				ImportStateVerify: true,
				// secret is sensitive and not stored on the import side
				// because import-by-id can't reconstruct user inputs;
				// the rest of the input attributes follow because the
				// resource is purely local-compute (Read passes state
				// through unchanged, so import lands an empty shell
				// keyed only by `id`).
				ImportStateVerifyIgnore: []string{"secret", "secret_encoding", "claims_json", "algorithm", "token"},
			},
		},
	})
}

// TestAccHashedTokenResource_replaceOnSecretChange asserts that
// changing `secret` triggers a full replacement (RequiresReplace plan
// modifier) rather than an in-place Update — Update is unreachable
// and would silently no-op if it ever got called.
func TestAccHashedTokenResource_replaceOnSecretChange(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "jwt_hashed_token" "example" {
  algorithm   = "HS256"
  secret      = "first-secret"
  claims_json = jsonencode({ a = "b" })
}
`,
			},
			{
				Config: `
resource "jwt_hashed_token" "example" {
  algorithm   = "HS256"
  secret      = "second-secret"
  claims_json = jsonencode({ a = "b" })
}
`,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("jwt_hashed_token.example", plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
			},
		},
	})
}

// TestAccHashedTokenResource_base64Secret confirms the secret_encoding
// switch decodes base64 secrets correctly. The expected token bytes
// match the SDK-v2 test fixture so a behavioural regression between
// the SDK and framework implementations would surface here.
func TestAccHashedTokenResource_base64Secret(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "jwt_hashed_token" "example" {
  algorithm       = "HS512"
  secret          = "ZX92vEaSMKXYAIF127SewQ=="
  secret_encoding = "base64"
  claims_json     = jsonencode({ a = "b" })
}
`,
				Check: resource.TestCheckResourceAttr(
					"jwt_hashed_token.example",
					"token",
					"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.zQB7DzBc37wOq-tsyDer8EysaWNEwA8rYq9fXFgWO9giMIkRwdCUYTUO27kY3nYFyDYRnVBMfOOYJ7X-l7LEIA",
				),
			},
		},
	})
}

// TestAccHashedTokenResource_invalidAlgorithm exercises the OneOf
// validator. The framework rejects the plan before reaching Create.
func TestAccHashedTokenResource_invalidAlgorithm(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "jwt_hashed_token" "example" {
  algorithm   = "RS256"
  secret      = "ignored"
  claims_json = jsonencode({})
}
`,
				ExpectError: regexpMatch(`Attribute algorithm value must be one of`),
			},
		},
	})
}

// TestAccHashedTokenResource_invalidClaims exercises the
// jsonObjectValidator.
func TestAccHashedTokenResource_invalidClaims(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "jwt_hashed_token" "example" {
  algorithm   = "HS256"
  secret      = "ignored"
  claims_json = "not json"
}
`,
				ExpectError: regexpMatch(`Invalid JSON`),
			},
		},
	})
}
