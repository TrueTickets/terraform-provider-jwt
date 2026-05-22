// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	jwtgen "github.com/golang-jwt/jwt/v5"
)

// TestSignJWT_RSA_RoundTrip drives signJWT directly and verifies the
// returned token round-trips against the matching public key. Avoids
// the Terraform lifecycle so it stays under a millisecond per run.
func TestSignJWT_RSA_RoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	privPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}))

	token, err := signJWT("RS256", privPEM, `{"sub":"alice"}`)
	if err != nil {
		t.Fatalf("signJWT: %v", err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("expected compact serialization, got %q", token)
	}

	parsed, err := jwtgen.Parse(token, func(*jwtgen.Token) (any, error) { return &priv.PublicKey, nil })
	if err != nil || !parsed.Valid {
		t.Fatalf("token failed verification: %v", err)
	}
	claims, _ := parsed.Claims.(jwtgen.MapClaims)
	if claims["sub"] != "alice" {
		t.Fatalf("claim sub: want alice, got %v", claims["sub"])
	}
}

// TestSignJWT_Errors covers the table of error paths so future
// refactors can't silently turn a failure into a successful
// nonsense-token.
func TestSignJWT_Errors(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	validRSAPEM := string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}))

	cases := []struct {
		name      string
		algorithm string
		pemKey    string
		claims    string
		want      string // substring expected in the error
	}{
		{"unknown algorithm", "ZZ999", validRSAPEM, `{}`, "not a supported signing algorithm"},
		{"hmac algorithm via signed resource", "HS256", validRSAPEM, `{}`, "doesn't know what key type"},
		{"invalid claims json", "RS256", validRSAPEM, `not json`, "not valid JSON"},
		{"unparseable key", "RS256", "garbage", `{}`, "parsing key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := signJWT(tc.algorithm, tc.pemKey, tc.claims)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

// TestTokenID confirms the SHA-256 hex digest is stable and the
// expected length (64 hex chars).
func TestTokenID(t *testing.T) {
	got := tokenID("eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.cl5DXDjjNUqWzYcsSOvljSs9skgxV7xrxXr6IFXdN_FEYe7qOw-IsWBQBAyB1Ra3kfngwT9h2VK1YuT00Qp-rg")
	if len(got) != 64 {
		t.Fatalf("tokenID length: want 64, got %d (%q)", len(got), got)
	}
	// Run twice and store separately so the comparison is opaque
	// to linters but still asserts determinism.
	first := tokenID("hello")
	second := tokenID("hello")
	if first != second {
		t.Fatal("tokenID is non-deterministic")
	}
	if tokenID("hello") == tokenID("world") {
		t.Fatal("tokenID collision on distinct inputs")
	}
}
