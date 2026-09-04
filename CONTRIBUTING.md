# Contributing

## Prerequisites

- **Go 1.26+**
- **Node.js 22+** and npm (for E2E tests only)

## Setup

```bash
git clone https://github.com/dominikschlosser/eudi-dev.git
cd eudi-dev
go build ./...
go test ./...
```

## Running Tests

```bash
# All tests
go test ./...

# With coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out

# Specific package
go test ./internal/sdjwt/...

# Verbose
go test -v -count=1 ./internal/wallet/...
```

### E2E Tests

E2E tests use Playwright. Its `webServer` builds the binary and starts `serve`, so the suite runs against a live server:

```bash
cd e2e
npm install
npx playwright install --with-deps chromium
npx playwright test
```

The Docker specs (`docker.spec.js`) need a running Docker daemon. Skip them with `--grep-invert docker`.

## Code Style

- Run `go vet ./...` before committing
- CI runs `golangci-lint` (errcheck, errorlint, gosec, govet, staticcheck, unused, plus gofmt and goimports as formatters)
- Imports: stdlib first, then external deps, then internal packages (enforced by goimports)
- Use `internal/jsonutil` for type assertions on `map[string]any`
- Defaults (ports, timeouts) go in `internal/config/defaults.go`

## Test Patterns

- Use `t.Helper()` in test helper functions
- Use `mock.GenerateKey()`, `mock.GenerateSDJWT()`, `mock.GenerateMDOC()` for test fixtures
- Table-driven tests with `t.Run()` for multiple cases
- Test files are in the same package as the code they test (`foo_test.go`)

## Project Structure

See [ARCHITECTURE.md](ARCHITECTURE.md) for package layout and data flow.

## Pull Requests

1. Create a feature branch from `main`
2. Ensure `go build ./...`, `go vet ./...`, and `go test ./...` pass
3. One feature or fix per PR
4. Update docs in `docs/` if adding or changing CLI flags

## Sign-off (DCO)

Every commit needs a [Developer Certificate of Origin](https://developercertificate.org/) sign-off. `git commit -s` adds the `Signed-off-by` trailer. Pull requests are checked for it. To sign off an existing branch: `git rebase --signoff main`.
