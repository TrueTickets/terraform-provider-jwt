# Terraform Provider for JSON Web Tokens

A Terraform/OpenTofu provider for generating JSON Web Tokens (JWTs)
inside your Terraform configuration. It supports HMAC-signed (`HS256`,
`HS384`, `HS512`) and asymmetric (`RS256/384/512`, `ES256/384/512`)
tokens.

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) >=
  1.0 (or [OpenTofu](https://opentofu.org/) >= 1.0)
- Go >= 1.25 (for building from source)

## Installation

### From the Terraform/OpenTofu registry

```hcl
terraform {
  required_providers {
    jwt = {
      source  = "truetickets/jwt"
      version = "~> 1.0"
    }
  }
}

provider "jwt" {}
```

### Building from source

```bash
git clone https://github.com/TrueTickets/terraform-provider-jwt.git
cd terraform-provider-jwt
go build -o terraform-provider-jwt
```

## Resources

### jwt_signed_token

Generates a JWT signed with an RSA or ECDSA private key.

```hcl
resource "jwt_signed_token" "example" {
  algorithm   = "RS256"
  key         = file("private-key.pem")
  claims_json = jsonencode({
    iss = "my-issuer"
    sub = "user-42"
    exp = timeadd(timestamp(), "1h")
  })
}

output "token" {
  value     = jwt_signed_token.example.token
  sensitive = true
}
```

| Attribute     | Type   | Required | Description                                                              |
| ------------- | ------ | -------- | ------------------------------------------------------------------------ |
| `algorithm`   | String | Yes      | Signing algorithm: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512`. |
| `key`         | String | Yes      | PEM-encoded private key matching `algorithm`. Sensitive.                 |
| `claims_json` | String | Yes      | The token's claims, as a JSON document.                                  |
| `token`       | String | Computed | The signed JWT, as a string. Sensitive.                                  |

### jwt_hashed_token

Generates a JWT signed with an HMAC secret.

```hcl
resource "jwt_hashed_token" "example" {
  algorithm   = "HS256"
  secret      = var.shared_secret
  claims_json = jsonencode({ sub = "user-42" })
}
```

| Attribute         | Type   | Required | Description                                                     |
| ----------------- | ------ | -------- | --------------------------------------------------------------- |
| `algorithm`       | String | No       | HMAC algorithm: `HS256`, `HS384`, `HS512`. Defaults to `HS512`. |
| `secret`          | String | Yes      | HMAC secret to sign the JWT with. Sensitive.                    |
| `secret_encoding` | String | No       | One of `raw`, `base64`, `hex`. Defaults to `raw`.               |
| `claims_json`     | String | Yes      | The token's claims, as a JSON document.                         |
| `token`           | String | Computed | The signed JWT, as a string. Sensitive.                         |

## Data Sources

### jwt_decoded_token

Decodes a JWT produced elsewhere into its header, claims, and signature
so downstream Terraform configuration can branch on individual claim
values. The signature is **not** verified — use this when the token's
trust is already established by other means (TLS, mTLS, key-rotated
upstream service).

```hcl
data "jwt_decoded_token" "example" {
  token = var.upstream_jwt
}

output "subject" {
  value = jsondecode(data.jwt_decoded_token.example.claims_json).sub
}
```

| Attribute       | Type   | Direction | Description                                              |
| --------------- | ------ | --------- | -------------------------------------------------------- |
| `token`         | String | In        | The compact-serialized JWT to decode. Sensitive.         |
| `header_json`   | String | Out       | JSON-encoded JWT header (JOSE header).                   |
| `claims_json`   | String | Out       | JSON-encoded JWT claims payload.                         |
| `signature_b64` | String | Out       | Base64url-encoded JWT signature (third compact segment). |
| `algorithm`     | String | Out       | Signing algorithm declared in the header `alg` claim.    |

## Development

### Build

```bash
task build       # or: go build -o terraform-provider-jwt
```

### Test

```bash
task test        # unit tests
task testacc     # acceptance tests (TF_ACC=1)
```

### Lint

```bash
task lint        # or: golangci-lint run
```

### Generate documentation

```bash
task generate
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full development
workflow.

## License

This provider is distributed under the
[Mozilla Public License 2.0](LICENSE). It incorporates code originally
licensed under the MIT License; see [NOTICE](NOTICE) for the preserved
upstream attribution.
