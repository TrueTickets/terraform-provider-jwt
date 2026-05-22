// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"
)

// TestDecodeJWT_KnownFixture decodes a hand-rolled HS512 token and
// asserts each output field exactly. The fixture is shared with the
// hashed-token acceptance test so the two tests cross-check each
// other.
func TestDecodeJWT_KnownFixture(t *testing.T) {
	const token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.cl5DXDjjNUqWzYcsSOvljSs9skgxV7xrxXr6IFXdN_FEYe7qOw-IsWBQBAyB1Ra3kfngwT9h2VK1YuT00Qp-rg"

	header, claims, sig, alg, err := decodeJWT(token)
	if err != nil {
		t.Fatalf("decodeJWT: %v", err)
	}
	if header != `{"alg":"HS512","typ":"JWT"}` {
		t.Fatalf("header: got %s", header)
	}
	if claims != `{"a":"b"}` {
		t.Fatalf("claims: got %s", claims)
	}
	if sig != "cl5DXDjjNUqWzYcsSOvljSs9skgxV7xrxXr6IFXdN_FEYe7qOw-IsWBQBAyB1Ra3kfngwT9h2VK1YuT00Qp-rg" {
		t.Fatalf("signature: got %s", sig)
	}
	if alg != "HS512" {
		t.Fatalf("algorithm: got %s", alg)
	}
}

// TestDecodeJWT_Errors covers the parser error paths.
func TestDecodeJWT_Errors(t *testing.T) {
	cases := []struct {
		name  string
		token string
		want  string
	}{
		{"empty", "", "token is empty"},
		{"whitespace", "   ", "token is empty"},
		{"not enough segments", "abc.def", "parsing token"},
		{"garbage segments", "not.a.jwt", "parsing token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, err := decodeJWT(tc.token)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
