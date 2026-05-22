// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// testAccProtoV6ProviderFactories is the provider map every acceptance
// test plugs into resource.TestCase. It serves the jwt provider via the
// in-process protocol-v6 transport that terraform-plugin-testing uses,
// so no external binary needs to be installed for the test run.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"jwt": providerserver.NewProtocol6WithError(New("test")()),
}

// testAccPreCheck is a no-op for the jwt provider: token signing is
// entirely local, so no environment variables, credentials, or
// network access need to be present. The function is kept in place
// for parity with the sibling provider repos and to give us a single
// hook if jwt ever grows configuration that needs validation at
// acceptance-test time.
func testAccPreCheck(_ *testing.T) {}

// regexpMatch is a thin wrapper around regexp.MustCompile used in
// TestStep.ExpectError so call sites stay readable.
func regexpMatch(pattern string) *regexp.Regexp {
	return regexp.MustCompile(pattern)
}
