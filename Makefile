# Image URL to use all building/pushing image targets
IMG ?= harbor.das-schiff.telekom.de/schiff-dev/breakglass-2:latest

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
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter
	$(GOLANGCI_LINT) run --timeout=5m

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix --timeout=5m

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet ## Run tests.
	@echo "Running unit tests..." && \
	go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out -v 2>&1 | tee test-output.log; \
	TEST_EXIT_CODE=$$?; \
	if [ $$TEST_EXIT_CODE -ne 0 ]; then \
		echo ""; \
		echo "=== TEST FAILURE DETECTED ==="; \
		echo "Exit code: $$TEST_EXIT_CODE"; \
		echo ""; \
		echo "=== FAILED TEST PACKAGES ==="; \
		grep "^FAIL" test-output.log | head -20; \
		echo ""; \
		echo "=== ERROR DETAILS ==="; \
		grep -A 10 "^---.*FAIL:" test-output.log | head -50; \
		echo ""; \
		echo "=== TEST OUTPUT LOG ==="; \
		tail -100 test-output.log; \
		exit $$TEST_EXIT_CODE; \
	fi

.PHONY: test-ci
test-ci: manifests generate fmt vet ## Run tests with enhanced CI diagnostics.
	@echo "=== CI TEST DIAGNOSTICS ===" && \
	echo "Go Version: $$(go version)" && \
	echo "Go Environment (key vars):" && \
	go env | grep -E "GO(OS|ARCH|VERSION|CACHE)" && \
	echo "" && \
	echo "=== RUNNING TESTS ===" && \
	go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out -v 2>&1 | tee test-output.log; \
	TEST_EXIT_CODE=$$?; \
	if [ $$TEST_EXIT_CODE -eq 0 ]; then \
		echo ""; \
		echo "✓ All tests PASSED"; \
		grep "^ok " test-output.log | wc -l | xargs -I {} echo "  {} packages passed"; \
	else \
		echo ""; \
		echo "✗ Tests FAILED with exit code: $$TEST_EXIT_CODE"; \
		echo ""; \
		echo "=== FAILED PACKAGES ==="; \
		grep "^FAIL" test-output.log; \
		echo ""; \
		echo "=== PANIC/ERROR TRACES ==="; \
		grep -E "panic|runtime error|fatal" test-output.log || echo "  No direct panic messages"; \
		echo ""; \
		echo "=== TEST FAILURES BY PACKAGE ==="; \
		grep "^--- FAIL:" test-output.log | sort | uniq -c; \
		echo ""; \
		echo "=== DETAILED FAILURE OUTPUT ==="; \
		grep -A 20 "^--- FAIL:" test-output.log | head -100; \
		echo ""; \
		echo "=== FULL TEST OUTPUT ==="; \
		cat test-output.log; \
	fi; \
	exit $$TEST_EXIT_CODE

.PHONY: test-verbose
test-verbose: manifests generate fmt vet ## Run tests with maximum verbosity and fresh cache.
	go test $$(go list ./... | grep -v /e2e) -coverprofile cover.out -v -count=1

.PHONY: e2e
e2e: ## Create a single kind cluster with breakglass, keycloak and mailhog deployed (no tests).
	# Run the single-cluster setup script which builds and loads images into kind
	# and deploys the controller, keycloak and mailhog. It writes hub kubeconfig to
	# e2e/kind-setup-single-hub-kubeconfig.yaml (repo-local) and exposes services for local use.
	bash e2e/kind-setup-single.sh

.PHONY: docker-build
docker-build: ## Build docker image with controller.
	docker build -t ${IMG} .

.PHONY: docker-build-oss
docker-build-oss: ## Build OSS (neutral UI) image
	docker build --build-arg UI_FLAVOUR=oss -t ${IMG:-breakglass:oss} .

.PHONY: docker-build-telekom
docker-build-telekom: ## Build Telekom branded UI image
	docker build --build-arg UI_FLAVOUR=telekom -t ${IMG:-breakglass:telekom} .

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
	cd config/deployment && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | $(KUBECTL) apply -f -

.PHONY: undeploy
undeploy: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy_dev # deploy dev environment with predefined config, service and dev keycloak
deploy_dev: kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/deployment && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/dev | $(KUBECTL) apply -f -

.PHONY: undeploy_dev
undeploy_dev: kustomize ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/dev | $(KUBECTL) delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: build_frontend
build_frontent:
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
CONTROLLER_TOOLS_VERSION ?= v0.16.4
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
KUSTOMIZE_VERSION ?= v5.6.0
CONTROLLER_TOOLS_VERSION ?= v0.16.4
ENVTEST_VERSION ?= release-1.19
GOLANGCI_LINT_VERSION ?= v1.64.4

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
	$(call go-install-tool,$(GOLANGCI_LINT),github.com/golangci/golangci-lint/cmd/golangci-lint,$(GOLANGCI_LINT_VERSION))


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
