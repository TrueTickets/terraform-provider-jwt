// Copyright (c) TrueTickets, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	jwtgen "github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// hashedTokenResource generates JWTs signed with an HMAC secret
// (HS256/HS384/HS512). The secret can be supplied as raw bytes, base64,
// or hex.
type hashedTokenResource struct{}

var (
	_ resource.Resource                = (*hashedTokenResource)(nil)
	_ resource.ResourceWithImportState = (*hashedTokenResource)(nil)
)

// NewHashedTokenResource is the constructor referenced by the provider.
func NewHashedTokenResource() resource.Resource {
	return &hashedTokenResource{}
}

// hashedTokenResourceModel is the tfsdk-tagged state shape.
type hashedTokenResourceModel struct {
	ID             types.String `tfsdk:"id"`
	Algorithm      types.String `tfsdk:"algorithm"`
	Secret         types.String `tfsdk:"secret"`
	SecretEncoding types.String `tfsdk:"secret_encoding"`
	Kid            types.String `tfsdk:"kid"`
	ClaimsJSON     types.String `tfsdk:"claims_json"`
	Token          types.String `tfsdk:"token"`
}

var (
	hmacAlgorithms   = []string{"HS256", "HS384", "HS512"}
	secretEncodings  = []string{"raw", "base64", "hex"}
	defaultAlgorithm = "HS512"
	defaultEncoding  = "raw"
)

func (r *hashedTokenResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_hashed_token"
}

func (r *hashedTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Generates a JWT signed with an HMAC secret " +
			"(HS256/HS384/HS512). The token is computed locally during apply " +
			"and stored in state as a sensitive computed attribute.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "SHA-256 hex digest of the signed token. " +
					"Stable for a given (algorithm, secret, secret_encoding, claims_json) tuple.",
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"algorithm": schema.StringAttribute{
				Description: "HMAC algorithm. One of `HS256`, `HS384`, `HS512`. " +
					"Defaults to `HS512`.",
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(defaultAlgorithm),
				Validators: []validator.String{
					stringvalidator.OneOf(hmacAlgorithms...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"secret": schema.StringAttribute{
				Description: "HMAC secret used to sign the JWT.",
				Required:    true,
				Sensitive:   true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"secret_encoding": schema.StringAttribute{
				Description: "How `secret` is encoded. One of `raw`, `base64`, " +
					"`hex`. Defaults to `raw`.",
				Optional: true,
				Computed: true,
				Default:  stringdefault.StaticString(defaultEncoding),
				Validators: []validator.String{
					stringvalidator.OneOf(secretEncodings...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"kid": schema.StringAttribute{
				Description: "Optional `kid` (key ID) value to set in the JWT " +
					"header so downstream verifiers can pick the matching " +
					"shared secret from a key registry.",
				Optional: true,
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

func (r *hashedTokenResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan hashedTokenResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	token, err := signHashedJWT(
		plan.Algorithm.ValueString(),
		plan.Secret.ValueString(),
		plan.SecretEncoding.ValueString(),
		plan.ClaimsJSON.ValueString(),
		plan.Kid.ValueString(),
	)
	if err != nil {
		resp.Diagnostics.AddError("Failed to sign JWT", err.Error())
		return
	}

	plan.Token = types.StringValue(token)
	plan.ID = types.StringValue(tokenID(token))

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *hashedTokenResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state hashedTokenResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *hashedTokenResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
}

func (r *hashedTokenResource) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

func (r *hashedTokenResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// signHashedJWT decodes the secret according to encoding, parses the
// claims, and signs the resulting JWT with the named HMAC algorithm.
// If kid is non-empty it is written into the JWT header so consumers
// looking up the shared secret by key ID can pick the right one.
func signHashedJWT(algorithm, rawSecret, encoding, claimsJSON, kid string) (string, error) {
	signer := jwtgen.GetSigningMethod(algorithm)
	if signer == nil {
		return "", fmt.Errorf("%s is not a supported HMAC algorithm", algorithm)
	}
	if _, isHMAC := signer.(*jwtgen.SigningMethodHMAC); !isHMAC {
		return "", fmt.Errorf("%s is not an HMAC algorithm; use jwt_signed_token for asymmetric keys", algorithm)
	}

	var secret []byte
	switch encoding {
	case "base64":
		var err error
		secret, err = base64.StdEncoding.DecodeString(rawSecret)
		if err != nil {
			return "", fmt.Errorf("decoding base64 secret: %w", err)
		}
	case "hex":
		var err error
		secret, err = hex.DecodeString(rawSecret)
		if err != nil {
			return "", fmt.Errorf("decoding hex secret: %w", err)
		}
	default:
		secret = []byte(rawSecret)
	}

	var claims map[string]any
	if err := json.Unmarshal([]byte(claimsJSON), &claims); err != nil {
		return "", fmt.Errorf("claims_json is not valid JSON: %w", err)
	}

	tok := jwtgen.NewWithClaims(signer, jwtgen.MapClaims(claims))
	if kid != "" {
		tok.Header["kid"] = kid
	}
	return tok.SignedString(secret)
}
