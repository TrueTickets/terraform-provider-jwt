# Generate an RSA-signed JWT.
resource "jwt_signed_token" "example" {
  algorithm = "RS256"
  key       = file("${path.module}/private-key.pem")

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
