# Changelog

All notable changes to this project will be documented in this file.

The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Pre-commit, golangci-lint, prettier, yamllint, and editorconfig
  configuration aligned with the sibling TrueTickets Terraform provider
  repositories.
- `Tests` GitHub Actions workflow with build, lint, generate, unit-test,
  and acceptance-test jobs.
- `Taskfile.yml` for local development tasks.
- Dependabot configuration for Go modules and GitHub Actions.
- `NOTICE` preserving the upstream MIT/Microsoft Corporation copyright
  notice required by the original license.

### Changed

- Relicensed under the Mozilla Public License 2.0 (was MIT).
- Renamed Go module to `github.com/truetickets/terraform-provider-jwt`.
- Bumped Go toolchain to 1.25.10.
- Narrowed goreleaser build matrix to `linux`/`darwin` × `amd64`/`arm64`
  and upgraded to schema v2.
- Rewrote `README.md` to reflect the actual resources shipped by this
  provider and the `truetickets/jwt` registry source.

### Fixed

- `claims_json` parse errors are now surfaced instead of silently
  producing an empty token payload.
- Internal `golangci-lint` cleanups in `jwt/` (errcheck,
  forcetypeassert, ineffassign, staticcheck).
