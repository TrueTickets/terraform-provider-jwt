package jwt

import (
	"encoding/json"
	"encoding/pem"
	"fmt"

	jwtgen "github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceSignedToken() *schema.Resource {
	return &schema.Resource{
		Description: "Generates a JWT signed with an asymmetric private key " +
			"(RSA or ECDSA). The token is computed locally during apply and " +
			"stored in state as a sensitive computed attribute.",
		Create: createSignedJWT,
		Delete: deleteSignedJWT,
		Read:   readSignedJWT,

		Schema: map[string]*schema.Schema{
			"algorithm": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "Signing algorithm to use.",
				ValidateFunc: validateSigningAlgorithm,
				ForceNew:     true,
			},
			"key": {
				Type:         schema.TypeString,
				Required:     true,
				Description:  "PEM-formated key to sign the JWT with.",
				ValidateFunc: validateSigningKey,
				ForceNew:     true,
				Sensitive:    true,
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

func createSignedJWT(d *schema.ResourceData, meta interface{}) (err error) {
	alg, _ := d.Get("algorithm").(string)
	signer := jwtgen.GetSigningMethod(alg)

	claims, _ := d.Get("claims_json").(string)

	jsonClaims := make(map[string]interface{})
	if err = json.Unmarshal([]byte(claims), &jsonClaims); err != nil {
		return fmt.Errorf("claims_json is not valid JSON: %w", err)
	}

	token := jwtgen.NewWithClaims(signer, jwtgen.MapClaims(jsonClaims))

	var key interface{}
	sKey, _ := d.Get("key").(string)

	if _, ok := signer.(*jwtgen.SigningMethodECDSA); ok {
		key, err = jwtgen.ParseECPrivateKeyFromPEM([]byte(sKey))
	} else if _, ok := signer.(*jwtgen.SigningMethodRSA); ok {
		key, err = jwtgen.ParseRSAPrivateKeyFromPEM([]byte(sKey))
	} else {
		err = fmt.Errorf("this provider doesn't know what key type goes with %s", alg)
	}
	if err != nil {
		return
	}

	signedToken, err := token.SignedString(key)
	if err != nil {
		return err
	}
	compactClaims, _ := json.Marshal(token.Claims)
	d.SetId(string(compactClaims))
	if err = d.Set("token", signedToken); err != nil {
		return err
	}
	return
}

func deleteSignedJWT(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func readSignedJWT(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func validateSigningAlgorithm(iAlg interface{}, k string) (warnings []string, errs []error) {
	alg, ok := iAlg.(string)
	if !ok {
		errs = append(errs, fmt.Errorf("%s must be a string", k))
		return
	}
	method := jwtgen.GetSigningMethod(alg)
	if method == nil {
		errs = append(errs, fmt.Errorf("%s is not a supported signing algorithm. Options are RS256, RS384, RS512, ES256, ES384, ES512", alg))
		return
	}
	if _, isHMAC := method.(*jwtgen.SigningMethodHMAC); isHMAC {
		errs = append(errs, fmt.Errorf("for HMAC signing, please use the jwt_hashed_token resource"))
	}
	return
}

func validateSigningKey(iKey interface{}, k string) (warnings []string, errs []error) {
	key, ok := iKey.(string)
	if !ok {
		errs = append(errs, fmt.Errorf("%s must be a string", k))
		return
	}
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		errs = append(errs, fmt.Errorf("%s must be PEM encoded", k))
	}
	// ideally we would validate that key was the right type (RSA vs ECDSA, but I don't think
	// validation functions can access multiple keys, so we'll just have to delay that til create time
	return
}
