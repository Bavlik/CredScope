## Summary

Describe the change and the user-visible outcome.

## Security and determinism

- [ ] No real credentials or private repository content are included.
- [ ] Raw-secret protections, path confinement, parser limits, and stable ordering are preserved.
- [ ] The CLI still performs no network access or repository code execution.
- [ ] Security-sensitive behavior has negative and leakage tests.

## Verification

- [ ] `gofmt` is clean.
- [ ] `go test -count=1 ./...` passes.
- [ ] `go vet ./...` passes.
- [ ] Documentation matches implemented behavior.
