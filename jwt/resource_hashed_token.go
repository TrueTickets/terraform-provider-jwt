package jwt

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	jwtgen "github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceHashedToken() *schema.Resource {
	return &schema.Resource{
		Description: "Generates a JWT signed with an HMAC secret " +
			"(HS256/HS384/HS512). The token is computed locally during apply " +
			"and stored in state as a sensitive computed attribute.",
		Create: createHashedJWT,
		Delete: deleteHashedJWT,
		Read:   readHashedJWT,

		Schema: map[string]*schema.Schema{
			"algorithm": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "HS512",
				Description:  "Signing algorithm to use. Defaults to `HS512`. Supported algorithms are `HS256`, `HS384`, `HS512`.",
				ValidateFunc: validateHashingAlgorithm,
				ForceNew:     true,
			},
			"secret": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "HMAC secret to sign the JWT with.",
				ForceNew:    true,
				Sensitive:   true,
			},
			"secret_encoding": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      "raw",
				Description:  "Secret encoding type. Defaults to `raw`. Supported algorithms are `raw`, `base64`, `hex`.",
				ValidateFunc: validateEncodingtype,
				ForceNew:     true,
			},
			"claims_json": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The token's claims, as a JSON document.",
				ForceNew:    true,
			},
			"token": {
				Type:        schema.TypeString,
				Description: "The JWT token, as a string.",
				Computed:    true,
				Sensitive:   true,
			},
		},
	}
}

func createHashedJWT(d *schema.ResourceData, meta interface{}) (err error) {
	alg, _ := d.Get("algorithm").(string)
	signer := jwtgen.GetSigningMethod(alg)

	claims, _ := d.Get("claims_json").(string)

	jsonClaims := make(map[string]interface{})
	if err = json.Unmarshal([]byte(claims), &jsonClaims); err != nil {
		return fmt.Errorf("claims_json is not valid JSON: %w", err)
	}

	token := jwtgen.NewWithClaims(signer, jwtgen.MapClaims(jsonClaims))

	secretEncoding, _ := d.Get("secret_encoding").(string)
	rawSecret, _ := d.Get("secret").(string)
	var secret []byte

	switch secretEncoding {
	case "base64":
		secret, err = base64.StdEncoding.DecodeString(rawSecret)
		if err != nil {
			return err
		}
	case "hex":
		secret, err = hex.DecodeString(rawSecret)
		if err != nil {
			return err
		}
	default:
		secret = []byte(rawSecret)
	}

	hashedToken, err := token.SignedString(secret)
	if err != nil {
		return err
	}
	compactClaims, _ := json.Marshal(token.Claims)
	d.SetId(string(compactClaims))
	if err = d.Set("token", hashedToken); err != nil {
		return err
	}
	return
}

func deleteHashedJWT(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func readHashedJWT(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func validateHashingAlgorithm(iAlg interface{}, k string) (warnings []string, errs []error) {
	alg, ok := iAlg.(string)
	if !ok {
		errs = append(errs, fmt.Errorf("%s must be a string", k))
		return
	}
	method := jwtgen.GetSigningMethod(alg)
	if method == nil {
		errs = append(errs, fmt.Errorf("%s is not a supported signing algorithm. Choices are HS256, HS384, HS512", alg))
		return
	}
	if _, isHMAC := method.(*jwtgen.SigningMethodHMAC); !isHMAC {
		errs = append(errs, fmt.Errorf("for RSA/ECDSA signing, please use the jwt_signed_token resource"))
	}
	return
}

func validateEncodingtype(iEnc interface{}, k string) (warnings []string, errs []error) {
	enc, ok := iEnc.(string)
	if !ok {
		errs = append(errs, fmt.Errorf("%s must be a string", k))
		return
	}
	if enc != "raw" && enc != "base64" && enc != "hex" {
		errs = append(errs, fmt.Errorf("%s is not a supported encoding type. Choices are raw, base64, hex", enc))
		return
	}
	return
}
