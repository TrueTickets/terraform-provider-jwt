# Generate an HMAC-signed JWT.
resource "jwt_hashed_token" "example" {
  algorithm = "HS256"
  secret    = var.shared_secret

  claims_json = jsonencode({
    sub = "user-42"
    exp = timeadd(timestamp(), "15m")
  })
}

variable "shared_secret" {
  type      = string
  sensitive = true
}

output "token" {
  value     = jwt_hashed_token.example.token
  sensitive = true
}
