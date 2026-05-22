// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"strings"
	"testing"

	jwtgen "github.com/golang-jwt/jwt/v5"
)

// TestSignHashedJWT_Encodings covers all three secret_encoding modes
// against the same plaintext key bytes. Each encoded form must
// produce the same token as the raw form, proving the decoding paths
// are equivalent.
func TestSignHashedJWT_Encodings(t *testing.T) {
	// Same secret expressed three ways.
	const rawSecret = "the-secret"
	const base64Secret = "dGhlLXNlY3JldA==" // base64.StdEncoding.EncodeToString([]byte(rawSecret))
	const hexSecret = "7468652d736563726574"

	cases := []struct {
		name     string
		secret   string
		encoding string
	}{
		{"raw", rawSecret, "raw"},
		{"base64", base64Secret, "base64"},
		{"hex", hexSecret, "hex"},
	}
	var first string
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := signHashedJWT("HS256", tc.secret, tc.encoding, `{"a":"b"}`, "")
			if err != nil {
				t.Fatalf("signHashedJWT: %v", err)
			}
			if first == "" {
				first = tok
			} else if tok != first {
				t.Fatalf("encoding %s produced %q; want %q", tc.encoding, tok, first)
			}
			// Independent verification with the same raw bytes.
			parsed, err := jwtgen.Parse(tok, func(*jwtgen.Token) (any, error) { return []byte(rawSecret), nil })
			if err != nil || !parsed.Valid {
				t.Fatalf("token failed verification: %v", err)
			}
		})
	}
}

// TestSignHashedJWT_KidHeader asserts the kid argument round-trips
// into the JWT header when set, and stays absent when empty. Mirrors
// TestSignJWT_KidHeader for the HMAC code path.
func TestSignHashedJWT_KidHeader(t *testing.T) {
	t.Run("kid present", func(t *testing.T) {
		token, err := signHashedJWT("HS256", "secret", "raw", `{"a":"b"}`, "my-key-id")
		if err != nil {
			t.Fatalf("signHashedJWT: %v", err)
		}
		parsed, _, err := jwtgen.NewParser().ParseUnverified(token, jwtgen.MapClaims{})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if got, _ := parsed.Header["kid"].(string); got != "my-key-id" {
			t.Fatalf("header kid: want %q, got %v", "my-key-id", parsed.Header["kid"])
		}
	})

	t.Run("kid omitted", func(t *testing.T) {
		token, err := signHashedJWT("HS256", "secret", "raw", `{"a":"b"}`, "")
		if err != nil {
			t.Fatalf("signHashedJWT: %v", err)
		}
		parsed, _, err := jwtgen.NewParser().ParseUnverified(token, jwtgen.MapClaims{})
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if _, present := parsed.Header["kid"]; present {
			t.Fatalf("header kid: want absent, got %v", parsed.Header["kid"])
		}
	})
}

// TestSignHashedJWT_Errors covers misuse paths: non-HMAC algorithm,
// invalid base64, invalid hex, invalid claims JSON.
func TestSignHashedJWT_Errors(t *testing.T) {
	cases := []struct {
		name      string
		algorithm string
		secret    string
		encoding  string
		claims    string
		want      string
	}{
		{"non-hmac algorithm", "RS256", "secret", "raw", `{}`, "is not an HMAC algorithm"},
		{"unknown algorithm", "ZZ999", "secret", "raw", `{}`, "not a supported HMAC algorithm"},
		{"bad base64", "HS256", "not!base64!", "base64", `{}`, "decoding base64 secret"},
		{"bad hex", "HS256", "zzz", "hex", `{}`, "decoding hex secret"},
		{"bad claims", "HS256", "secret", "raw", `not json`, "not valid JSON"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := signHashedJWT(tc.algorithm, tc.secret, tc.encoding, tc.claims, "")
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
