# Generate an RSA-signed JWT.
resource "jwt_signed_token" "example" {
  algorithm = "RS256"
  key       = file("${path.module}/private-key.pem")

  # Optional. When set, "kid" is written into the JWT header so
  # consumers can pick the right public key out of a multi-key JWKS
  # (for example, Google service-account JWKS endpoints).
  kid = "service-account-key-id"

  claims_json = jsonencode({
    iss = "my-issuer"
    sub = "user-42"
    aud = "my-audience"
    exp = timeadd(timestamp(), "1h")
  })
}

output "token" {
  value     = jwt_signed_token.example.token
  sensitive = true
}
