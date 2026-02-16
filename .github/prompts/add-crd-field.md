You are adding a new CRD field to the breakglass controller. Follow these steps:

## Steps

1. Add the field to `api/v1alpha1/*_types.go` with kubebuilder markers
2. Run `make generate && make manifests`
3. Update webhook validation in `api/v1alpha1/*_webhook.go`
4. Add fuzz test coverage in `api/v1alpha1/fuzz_test.go`
5. Update controller/handler logic in `pkg/breakglass/`
6. Update REST API if the field is exposed via HTTP in `pkg/api/`
7. Add unit tests for the new field behavior
8. Update docs: `docs/` relevant files
9. Update Helm chart: `charts/escalation-config/`
10. Update CHANGELOG.md
11. Run `make lint test` and `cd frontend && npm test`
