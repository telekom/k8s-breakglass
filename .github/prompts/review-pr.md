You are reviewing a pull request for k8s-breakglass. Check for:

## Code Quality
- [ ] Auto-generated files are up to date (`make generate && make manifests`)
- [ ] `go mod tidy` has been run
- [ ] Uses `http.MethodGet` etc. instead of string literals
- [ ] Errors wrapped with `%w` not `%v`
- [ ] No `log.Fatal()` / `os.Exit()` in library code

## Testing
- [ ] Go unit tests added/updated (>70% coverage)
- [ ] Frontend tests pass (`cd frontend && npm test`)
- [ ] Fuzz tests updated if API types changed
- [ ] E2E sessions use API helpers, not direct K8s client

## Security
- [ ] No hardcoded credentials or secrets
- [ ] RBAC markers use least privilege
- [ ] SPDX headers on all new files

## Documentation
- [ ] CHANGELOG.md updated for user-facing changes
- [ ] API reference updated if endpoints changed
- [ ] Helm chart values documented if config added
- [ ] Frontend docs updated if UI changed
