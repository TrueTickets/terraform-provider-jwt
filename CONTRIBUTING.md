# Contributing to terraform-provider-jwt

Thanks for considering a contribution! This provider lives alongside the
other TrueTickets Terraform providers and follows the same conventions
for tooling, layout, and review.

## Development requirements

- Go 1.25+
- [Terraform](https://developer.hashicorp.com/terraform/downloads) 1.0+
  or [OpenTofu](https://opentofu.org/) 1.0+
- [go-task](https://taskfile.dev/) (`brew install go-task`)
- [pre-commit](https://pre-commit.com/) (`brew install pre-commit`)
- [golangci-lint](https://golangci-lint.run/) 2.x
  (`brew install golangci-lint`)

## Getting started

1. Fork and clone the repository.
2. Install pre-commit hooks so checks run automatically:
    ```bash
    pre-commit install
    ```
3. Fetch dependencies and build:
    ```bash
    go mod download
    task build
    ```

## Development workflow

### 1. Make your changes

- The provider is built on
  [terraform-plugin-framework](https://developer.hashicorp.com/terraform/plugin/framework)
  v1.x and speaks Terraform plugin protocol 6.
- Resources and data sources live in `internal/provider/`. Each one
  follows the convention `<thing>_resource.go` /
  `<thing>_data_source.go` with three test files alongside:
    - `<thing>_test.go` — pure-function unit tests
    - `<thing>_acc_test.go` — Terraform-lifecycle acceptance tests
    - Shared helpers in `provider_acc_test.go`

### 2. Write tests

- Add unit tests in `<thing>_test.go` for any new helper function. They
  run on every `task test`.
- Add acceptance tests in `<thing>_acc_test.go` using
  `resource.Test(t, resource.TestCase{...})`. Aim for at least one step
  that exercises Create + Read, one `ConfigPlanChecks` step that proves
  the plan is empty on re-apply, and (for resources) one
  `ImportStateVerify` step.
- Acceptance tests for this provider are fully hermetic — the resources
  do not call any external API, so no credentials are needed.

### 3. Run quality checks

```bash
task fmt        # gofmt -s -w -e .
task lint       # golangci-lint run
task test       # go test -v -cover -timeout=120s -parallel=10 ./...
task testacc    # TF_ACC=1 go test -v -cover -timeout 120m ./...
task generate   # regenerate docs/ from templates/ + examples/
```

`pre-commit run --all-files` mirrors what CI runs on each PR.

### 4. Update documentation

- Add or update templates in `templates/`.
- Add or update example Terraform in `examples/`.
- Run `task generate` to regenerate `docs/`. Commit the regenerated
  files; CI fails if `docs/` drifts from what `tfplugindocs` would
  produce.

## Commit messages

Use the conventional commit format with a short imperative subject:

- `feat:` new functionality
- `fix:` bug fix
- `docs:` documentation only
- `test:` tests only
- `refactor:` no functional change
- `build:` build / release tooling
- `ci:` CI configuration
- `chore:` everything else

Keep the subject line under ~72 characters and describe the _why_ in the
body using semantic line breaks.

## Pull request process

1. Branch from `main`.
2. Make atomic commits — one logical change per commit.
3. Update `CHANGELOG.md` under `[Unreleased]`.
4. Ensure `task lint`, `task test`, and `pre-commit run --all-files` are
   clean locally.
5. Open a PR using the template; address review feedback in follow-up
   commits (avoid rewriting history once review has started).

## Releasing

Tagged releases (`vX.Y.Z`) trigger the `Release` workflow, which uses
goreleaser to build artifacts for `linux`/`darwin` × `amd64`/`arm64`,
sign the checksums with the repository's GPG key, and attach the
terraform registry manifest. Do not tag from a feature branch — tags
should come off `main` after merge.

## Questions?

Open an issue or reach out in the team Slack. Thanks for contributing!
