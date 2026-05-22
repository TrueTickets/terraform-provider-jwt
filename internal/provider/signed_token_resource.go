// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	jwtgen "github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// signedTokenResource generates JWTs signed with an asymmetric private
// key (RSA or ECDSA). All inputs are RequiresReplace because the
// resulting token is deterministic in the inputs.
type signedTokenResource struct{}

var (
	_ resource.Resource                = (*signedTokenResource)(nil)
	_ resource.ResourceWithImportState = (*signedTokenResource)(nil)
)

// NewSignedTokenResource is the constructor referenced by the provider.
func NewSignedTokenResource() resource.Resource {
	return &signedTokenResource{}
}

// signedTokenResourceModel is the tfsdk-tagged state shape.
type signedTokenResourceModel struct {
	ID         types.String `tfsdk:"id"`
	Algorithm  types.String `tfsdk:"algorithm"`
	Key        types.String `tfsdk:"key"`
	ClaimsJSON types.String `tfsdk:"claims_json"`
	Token      types.String `tfsdk:"token"`
}

// signedAlgorithms is the allowlist of asymmetric algorithms this
// resource accepts. HMAC algorithms belong on jwt_hashed_token.
var signedAlgorithms = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

func (r *signedTokenResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_signed_token"
}

func (r *signedTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Generates a JWT signed with an asymmetric private key " +
			"(RSA or ECDSA). The token is computed locally during apply and " +
			"stored in state as a sensitive computed attribute.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "SHA-256 hex digest of the signed token. " +
					"Stable for a given (algorithm, key, claims_json) tuple.",
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"algorithm": schema.StringAttribute{
				Description: "Signing algorithm. One of " +
					"`RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`.",
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(signedAlgorithms...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"key": schema.StringAttribute{
				Description: "PEM-encoded RSA or ECDSA private key matching `algorithm`.",
				Required:    true,
				Sensitive:   true,
				Validators: []validator.String{
					pemEncodedValidator{},
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"claims_json": schema.StringAttribute{
				Description: "The token's claims, as a JSON object.",
				Required:    true,
				Validators: []validator.String{
					jsonObjectValidator{},
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"token": schema.StringAttribute{
				Description: "The signed JWT, as a compact-serialized string.",
				Computed:    true,
				Sensitive:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *signedTokenResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan signedTokenResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	token, err := signJWT(plan.Algorithm.ValueString(), plan.Key.ValueString(), plan.ClaimsJSON.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to sign JWT", err.Error())
		return
	}

	plan.Token = types.StringValue(token)
	plan.ID = types.StringValue(tokenID(token))

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read passes the existing state through unchanged. JWTs are local and
// deterministic; there is no remote system to query and no drift to
// detect.
func (r *signedTokenResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state signedTokenResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is unreachable in practice — every input attribute is
// RequiresReplace — but the framework requires the method to exist.
func (r *signedTokenResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
}

// Delete is a no-op: there is no remote state to clean up.
func (r *signedTokenResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ImportState accepts the resource's `id` (a SHA-256 hex of the
// previously-signed token) as the import argument. The user is
// expected to reconstruct the matching algorithm/key/claims_json in
// configuration; a subsequent plan will compare and either pass
// cleanly or trigger a replace.
func (r *signedTokenResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// signJWT signs the given claims with the given PEM-encoded private
// key, dispatching on the algorithm family.
func signJWT(algorithm, pemKey, claimsJSON string) (string, error) {
	signer := jwtgen.GetSigningMethod(algorithm)
	if signer == nil {
		return "", fmt.Errorf("%s is not a supported signing algorithm", algorithm)
	}

	var claims map[string]any
	if err := json.Unmarshal([]byte(claimsJSON), &claims); err != nil {
		return "", fmt.Errorf("claims_json is not valid JSON: %w", err)
	}

	var key any
	var err error
	switch signer.(type) {
	case *jwtgen.SigningMethodECDSA:
		key, err = jwtgen.ParseECPrivateKeyFromPEM([]byte(pemKey))
	case *jwtgen.SigningMethodRSA:
		key, err = jwtgen.ParseRSAPrivateKeyFromPEM([]byte(pemKey))
	default:
		return "", fmt.Errorf("this provider doesn't know what key type goes with %s", algorithm)
	}
	if err != nil {
		return "", fmt.Errorf("parsing key: %w", err)
	}

	tok := jwtgen.NewWithClaims(signer, jwtgen.MapClaims(claims))
	return tok.SignedString(key)
}

// tokenID returns the SHA-256 hex digest of a signed JWT.
func tokenID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
