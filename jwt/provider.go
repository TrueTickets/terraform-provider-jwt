package jwt

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Provider returns the jwt provider to serve as a plugin.
func Provider() *schema.Provider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"jwt_hashed_token": resourceHashedToken(),
			"jwt_signed_token": resourceSignedToken(),
		},
		DataSourcesMap: map[string]*schema.Resource{},
	}
}
