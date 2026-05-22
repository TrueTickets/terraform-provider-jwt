# Decode a JWT that was produced elsewhere into its header, claims,
# and signature so individual claim values can drive other Terraform
# resources.
data "jwt_decoded_token" "example" {
  token = var.upstream_jwt
}

variable "upstream_jwt" {
  type      = string
  sensitive = true
}

output "subject" {
  value = jsondecode(data.jwt_decoded_token.example.claims_json).sub
}
