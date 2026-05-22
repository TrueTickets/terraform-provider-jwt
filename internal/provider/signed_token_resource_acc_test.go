// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	jwtgen "github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// TestAccSignedTokenResource_lifecycle exercises the full RSA path
// end-to-end: Create + Read, an empty re-apply to prove the computed
// attributes survive refresh, and ImportStateVerify. RSA-PKCS1v15
// signing is deterministic, so the same key + claims produce the same
// token byte-for-byte across runs.
func TestAccSignedTokenResource_lifecycle(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	privPEM := encodePKCS1PrivateKey(t, priv)

	config := fmt.Sprintf(`
resource "jwt_signed_token" "example" {
  algorithm   = "RS256"
  key         = %q
  claims_json = jsonencode({ sub = "user-42" })
}
`, privPEM)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create + verify the token round-trips against
			// the matching public key.
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("jwt_signed_token.example", "token"),
					resource.TestCheckResourceAttrSet("jwt_signed_token.example", "id"),
					resource.TestCheckResourceAttr("jwt_signed_token.example", "algorithm", "RS256"),
					verifyRSAToken("jwt_signed_token.example", &priv.PublicKey, map[string]any{"sub": "user-42"}),
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
			// Step 3: ImportStateVerify. All inputs are sensitive or
			// computed-from-config; the import-by-id path can only
			// recover the id itself.
			{
				ResourceName:            "jwt_signed_token.example",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"algorithm", "key", "claims_json", "token"},
			},
		},
	})
}

// TestAccSignedTokenResource_replaceOnClaimsChange asserts that
// changing claims_json triggers a destroy+create instead of an
// in-place update.
func TestAccSignedTokenResource_replaceOnClaimsChange(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	privPEM := encodePKCS1PrivateKey(t, priv)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "jwt_signed_token" "example" {
  algorithm   = "RS256"
  key         = %q
  claims_json = jsonencode({ sub = "a" })
}
`, privPEM),
			},
			{
				Config: fmt.Sprintf(`
resource "jwt_signed_token" "example" {
  algorithm   = "RS256"
  key         = %q
  claims_json = jsonencode({ sub = "b" })
}
`, privPEM),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("jwt_signed_token.example", plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
			},
		},
	})
}

// TestAccSignedTokenResource_rejectsHMACAlgorithm asserts that the
// OneOf validator on `algorithm` keeps HMAC values out of the
// signed-token resource at plan time.
func TestAccSignedTokenResource_rejectsHMACAlgorithm(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "jwt_signed_token" "example" {
  algorithm   = "HS256"
  key         = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
  claims_json = jsonencode({})
}
`,
				ExpectError: regexpMatch(`Attribute algorithm value must be one of`),
			},
		},
	})
}

// TestAccSignedTokenResource_kidEndToEnd is the integration test for
// the kid header — the feature this provider was forked to add. The
// resource signs a token with a kid, the data source decodes the
// header, and the test asserts the kid round-tripped intact. This
// catches any future regression that drops or mangles the header
// between Create and the wire format.
func TestAccSignedTokenResource_kidEndToEnd(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	privPEM := encodePKCS1PrivateKey(t, priv)

	cfg := fmt.Sprintf(`
resource "jwt_signed_token" "with_kid" {
  algorithm   = "RS256"
  key         = %q
  kid         = "service-account-key-2026"
  claims_json = jsonencode({ sub = "robot" })
}

data "jwt_decoded_token" "decoded" {
  token = jwt_signed_token.with_kid.token
}
`, privPEM)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("jwt_signed_token.with_kid", "kid", "service-account-key-2026"),
					// The header_json string is order-stable for the
					// fields tfplugindocs emits because the underlying
					// JOSE library uses an alphabetical map encoder.
					resource.TestCheckResourceAttr(
						"data.jwt_decoded_token.decoded",
						"header_json",
						`{"alg":"RS256","kid":"service-account-key-2026","typ":"JWT"}`,
					),
				),
			},
		},
	})
}

// TestAccSignedTokenResource_rejectsNonPEMKey exercises the
// pemEncodedValidator.
func TestAccSignedTokenResource_rejectsNonPEMKey(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
resource "jwt_signed_token" "example" {
  algorithm   = "RS256"
  key         = "not a key"
  claims_json = jsonencode({})
}
`,
				ExpectError: regexpMatch(`Invalid PEM`),
			},
		},
	})
}

// encodePKCS1PrivateKey returns a PKCS#1 PEM block for the given key.
// The golang-jwt parser accepts both PKCS#1 and PKCS#8 PEMs; PKCS#1
// keeps the test fixture shorter.
func encodePKCS1PrivateKey(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}))
}

// verifyRSAToken returns a TestCheckFunc that parses the resource's
// token attribute and verifies it against pubKey, then checks the
// claim set matches expected. This is the framework equivalent of the
// SDK-era "round-trip" pattern.
func verifyRSAToken(resourceName string, pubKey *rsa.PublicKey, expected map[string]any) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %q not found in state", resourceName)
		}
		token := rs.Primary.Attributes["token"]
		if token == "" {
			return fmt.Errorf("resource %q has empty token", resourceName)
		}

		parsed, err := jwtgen.Parse(token, func(t *jwtgen.Token) (any, error) {
			if _, ok := t.Method.(*jwtgen.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method %T", t.Method)
			}
			return pubKey, nil
		})
		if err != nil {
			return fmt.Errorf("verifying token: %w", err)
		}
		if !parsed.Valid {
			return fmt.Errorf("token failed verification")
		}

		claims, ok := parsed.Claims.(jwtgen.MapClaims)
		if !ok {
			return fmt.Errorf("unexpected claims type %T", parsed.Claims)
		}
		for k, v := range expected {
			got, present := claims[k]
			if !present {
				return fmt.Errorf("claim %q missing from %v", k, claims)
			}
			if !strings.EqualFold(fmt.Sprint(got), fmt.Sprint(v)) {
				return fmt.Errorf("claim %q: want %v, got %v", k, v, got)
			}
		}
		return nil
	}
}
