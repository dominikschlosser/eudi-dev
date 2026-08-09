# Contributing

## Prerequisites

- **Go 1.26+**
- **Node.js 22+** and npm (for E2E tests only)

## Setup

```bash
git clone https://github.com/dominikschlosser/eudi-dev.git
cd oid4vc-dev
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

E2E tests use Playwright. The Playwright `webServer` builds and starts the
binary's `serve` command, so the suite drives a live server:

```bash
cd e2e
npm install
npx playwright install --with-deps chromium   # download the browser (npm install does not)
npx playwright test
```

Some specs (`docker.spec.js`) build and run a Docker image, so they need a
running Docker daemon; skip them with `--grep-invert docker` if Docker is
unavailable.

## Code Style

- Run `go vet ./...` before committing
- CI runs `golangci-lint` (errcheck, gofmt, goimports, govet, staticcheck)
- Imports: stdlib first, then external deps, then internal packages (enforced by goimports)
- Use `internal/jsonutil` for type assertions on `map[string]any` instead of inline casts
- Constants (ports, timeouts) go in `internal/config/defaults.go`

## Test Patterns

- Use `t.Helper()` in test helper functions
- Use `mock.GenerateKey()`, `mock.GenerateSDJWT()`, `mock.GenerateMDOC()` for test fixtures
- Table-driven tests with `t.Run()` for multiple cases
- Test files live next to the code they test (`foo_test.go` in the same package)

## Project Structure

See [ARCHITECTURE.md](ARCHITECTURE.md) for package layout and data flow.

## Pull Requests

1. Create a feature branch from `main`
2. Ensure `go build ./...`, `go vet ./...`, and `go test ./...` pass
3. Keep changes focused. One feature or fix per PR
4. Update docs in `docs/` if adding or changing CLI flags
