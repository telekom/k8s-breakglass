include versions.env

# Image URL to use all building/pushing image targets
IMG ?= ghcr.io/telekom/k8s-breakglass:latest

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

HACK_BIN=$(shell pwd)/hack/bin

# Setting SHELL to bash allows bash commands to be executed by recipes.
# Options are set to exit when a recipe line exits non-zero or a piped command fails.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec


##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk command is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd/bases

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, DeepCopyObject, and ApplyConfiguration method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."
	$(CONTROLLER_GEN) applyconfiguration:headerFile="hack/boilerplate.go.txt" paths="./api/..."

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run --timeout=5m

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix --timeout=5m

.PHONY: lint-verbose
lint-verbose: golangci-lint ## Run golangci-lint with verbose output
	$(GOLANGCI_LINT) run --timeout=5m -v

.PHONY: lint-new
lint-new: golangci-lint ## Run golangci-lint only on new/changed code (requires git)
	$(GOLANGCI_LINT) run --timeout=5m --new

.PHONY: lint-strict
lint-strict: golangci-lint ## Run golangci-lint with extended timeout (CI-friendly).
	$(GOLANGCI_LINT) run --timeout 10m

.PHONY: vulncheck
vulncheck: ## Run govulncheck to check for known vulnerabilities.
	@command -v govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(shell go env GOPATH)/bin/govulncheck ./...

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet ## Run tests.
	go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out

.PHONY: validate-samples
validate-samples: manifests ## Validate all YAML samples in config/samples against CRD schemas.
	@echo "Validating sample YAML files..."
	go test ./api/v1alpha1/... -run TestSamplesAreValid -v
	@echo "Sample validation passed"

.PHONY: verify
verify: fmt vet lint-strict test vulncheck ## Run all verification checks (fmt, vet, lint, test, vulncheck).
	go build ./...
	@echo "All verification checks passed!"

.PHONY: e2e
e2e: ## Create a single kind cluster with breakglass, keycloak and mailhog deployed (no tests).
	# Run the single-cluster setup script which builds and loads images into kind
	# and deploys the controller, keycloak and mailhog. It writes hub kubeconfig to
	# e2e/kind-setup-single-hub-kubeconfig.yaml (repo-local) and exposes services for local use.
	bash e2e/kind-setup-single.sh

.PHONY: bgctl
bgctl: build-bgctl ## Alias for build-bgctl

.PHONY: build-bgctl
build-bgctl: ## Build the bgctl CLI binary
	@GIT_COMMIT=$$(git rev-parse --short HEAD 2>/dev/null || echo "unknown"); \
	GIT_DIRTY=$$(git diff --quiet 2>/dev/null || echo "-dirty"); \
	BUILD_DATE=$$(date -u '+%Y-%m-%dT%H:%M:%SZ'); \
	VERSION=$${VERSION:-dev}; \
	echo "Building bgctl $$VERSION (commit: $$GIT_COMMIT$$GIT_DIRTY, built: $$BUILD_DATE)"; \
	CGO_ENABLED=0 go build \
		-ldflags "-X github.com/telekom/k8s-breakglass/pkg/version.Version=$$VERSION \
		-X github.com/telekom/k8s-breakglass/pkg/version.GitCommit=$$GIT_COMMIT$$GIT_DIRTY \
		-X github.com/telekom/k8s-breakglass/pkg/version.BuildDate=$$BUILD_DATE" \
		-o bin/bgctl ./cmd/bgctl

.PHONY: test-cli
test-cli: ## Run bgctl unit tests
	go test -v ./pkg/bgctl/...

.PHONY: test-cli-e2e
test-cli-e2e: ## Run bgctl CLI tests (basic tests only - full E2E requires E2E_TEST=true with kind cluster)
	go test -v ./e2e/cli/...

# Version and build metadata
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

.PHONY: docker-build
docker-build: ## Build docker image with controller.
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t ${IMG} .

.PHONY: docker-build-oss
docker-build-oss: ## Build OSS (neutral UI) image
	docker build \
		--build-arg UI_FLAVOUR=oss \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t ${IMG:-breakglass:oss} .

.PHONY: docker-build-telekom
docker-build-telekom: ## Build Telekom branded UI image
	docker build \
		--build-arg UI_FLAVOUR=telekom \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t ${IMG:-breakglass:telekom} .

.PHONY: docker-build-dev
docker-build-dev: ## Build docker image with controller.
	docker build -t breakglass:dev .

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) apply -f -

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy # manifests
deploy: kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/deployment && $(KUSTOMIZE) edit set image breakglass=${IMG}
	$(KUSTOMIZE) build config/base | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/base | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy_debug # deploy with debug logging enabled
deploy_debug: kustomize ## Deploy controller with debug logging to the K8s cluster specified in ~/.kube/config.
	cd config/deployment && $(KUSTOMIZE) edit set image breakglass=${IMG}
	$(KUSTOMIZE) build config/debug | $(KUBECTL) apply -f -

.PHONY: undeploy_debug
undeploy_debug: kustomize ## Undeploy debug controller from the K8s cluster.
	$(KUSTOMIZE) build config/debug | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy_dev # deploy dev environment with predefined config, service and dev keycloak
deploy_dev: kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/dev && ./generate-certs.sh && cd ../..
	cd config/deployment && $(KUSTOMIZE) edit set image breakglass=${IMG}
	$(KUSTOMIZE) build config/dev | $(KUBECTL) apply -f -

.PHONY: undeploy_dev
undeploy_dev: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/dev | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: build_frontend
build_frontend:
	cd frontend && npm i && npm run build

.PHONY: samples
samples: 
	$(KUBECTL) create -f config/samples/

##@ Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUSTOMIZE ?= $(LOCALBIN)/kustomize
KUBECTL ?= kubectl
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary.
$(KUSTOMIZE): $(LOCALBIN)
	$(call go-install-tool,$(KUSTOMIZE),sigs.k8s.io/kustomize/kustomize/v5,$(KUSTOMIZE_VERSION))

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary.
$(CONTROLLER_GEN): $(LOCALBIN)
	$(call go-install-tool,$(CONTROLLER_GEN),sigs.k8s.io/controller-tools/cmd/controller-gen,$(CONTROLLER_TOOLS_VERSION))

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/v2/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))

.PHONY: helm-validate
helm-validate: ## Validate Helm chart syntax and templates for escalation-config
	helm lint charts/escalation-config --strict
	helm template escalation-config charts/escalation-config > /dev/null
	@echo "Helm chart validation passed"

# go-install-tool will 'go install' any package with custom target and name of binary, if it doesn't exist
# $1 - target path with name of binary
# $2 - package url which can be installed
# $3 - specific version of package
define go-install-tool
@[ -f "$(1)-$(3)" ] || { \
set -e; \
package=$(2)@$(3) ;\
echo "Downloading $${package}" ;\
rm -f $(1) || true ;\
GOBIN=$(LOCALBIN) go install $${package} ;\
mv $(1) $(1)-$(3) ;\
} ;\
ln -sf $(1)-$(3) $(1)
endef
##@ Release

RELEASE_TAG ?= $(shell git describe --tags --abbrev=0 2>/dev/null)

RELEASE_DIR ?= out

$(RELEASE_DIR):
	mkdir -p $(RELEASE_DIR)/
