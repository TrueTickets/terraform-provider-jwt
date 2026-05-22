# Changelog

All notable changes to this project will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - Unreleased

First release of the provider under the `truetickets/jwt` namespace. The
provider is a near-complete rewrite of the upstream `geektheripper/jwt`
plugin onto the HashiCorp Terraform Plugin Framework. There is no
automatic state-upgrade path from upstream state files; treat this as a
fresh install.

### Added

- **New Resource:** `jwt_signed_token` — generates a JWT signed with an
  RSA or ECDSA private key (RS256/384/512, ES256/384/512).
- **New Resource:** `jwt_hashed_token` — generates a JWT signed with an
  HMAC secret (HS256/384/512), with `raw`, `base64`, or `hex` secret
  encoding.
- **New Data Source:** `jwt_decoded_token` — decodes a JWT into its
  header, claims, and signature without verifying the signature.
- Optional `kid` (key ID) attribute on both resources. When set, the
  value is written into the JWT header so downstream verifiers can look
  up the matching public key from a JWKS (for example, Google
  service-account JWKS endpoints). This is the headline reason the
  upstream `geektheripper/jwt` provider was forked.
- ImportState support on both resources via the SHA-256 token id.
- Pre-commit, golangci-lint, prettier, yamllint, and editorconfig
  configuration aligned with the sibling TrueTickets Terraform provider
  repositories.
- `Tests` GitHub Actions workflow with build, lint, generate-diff, unit,
  and acceptance-test jobs.
- `Taskfile.yml` for local development tasks.
- Dependabot configuration for Go modules and GitHub Actions.
- `NOTICE` preserving the upstream MIT/Microsoft Corporation copyright
  notice required by the original license.

### Changed

- Migrated to `terraform-plugin-framework` v1.19.0; the provider now
  speaks Terraform plugin protocol 6 instead of 5.
- Resource layout moves from a top-level `jwt/` package to
  `internal/provider/` with one file per resource and per test layer.
- Resource IDs are now SHA-256 hex digests of the signed token instead
  of the compact JSON of the claims (which leaked claim contents into
  Terraform diagnostics output).
- Provider address baked into `main.go` is now
  `registry.opentofu.org/truetickets/jwt`.
- Relicensed under the Mozilla Public License 2.0 (was MIT).
- Renamed Go module to `github.com/truetickets/terraform-provider-jwt`.
- Bumped Go toolchain to 1.25.10.
- Narrowed goreleaser build matrix to `linux`/`darwin` × `amd64`/`arm64`
  and upgraded to schema v2.
- `claims_json` is now validated at plan time: it must parse as a JSON
  object (RFC 7519 §4 requires an object). Invalid input is rejected
  before reaching Create.

### Fixed

- `claims_json` parse errors are now surfaced instead of silently
  producing an empty token payload.
- Internal `golangci-lint` cleanups (errcheck, forcetypeassert,
  ineffassign, staticcheck).

### Removed

- `terraform-plugin-sdk/v2` as a direct dependency. The test harness
  still pulls it transitively via `terraform-plugin-testing`.
