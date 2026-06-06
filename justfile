set shell := ["sh", "-c"]
set export

BIN := "bin"
IMAGE := "ghcr.io/axoflow/axoflow-idp"
GOLANGCI_LINT := BIN / "golangci-lint"
LICENSEI := BIN / "licensei"
EDITORCONFIG_CHECKER := BIN / "editorconfig-checker"

GOLANGCI_LINT_VERSION := "2.6.2"
LICENSEI_VERSION := "0.9.0"
EDITORCONFIG_CHECKER_VERSION := "3.6.0"
GOVERSION := `go env GOVERSION`


[private]
default:
    @just --list

verify: editor-config lint-go license-check test

test:
    go test -v ./...

# Run all unit/integration tests with the race detector.
test-race:
    go test -race ./...

# Run the end-to-end suite: builds the server and drives the real HTTP flows.
test-e2e:
    python3 scripts/e2e.py

# Build the container image (matches the name published by CI).
image:
    docker build -t {{IMAGE}} .

# Build into minikube's Docker (tag :dev) and deploy to axoflow-local (local dev).
minikube-deploy:
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(minikube docker-env)"
    docker build -t {{IMAGE}}:dev .
    kubectl -n axoflow-local set image deployment/axoidp '*={{IMAGE}}:dev'
    kubectl -n axoflow-local rollout status deployment/axoidp --timeout=120s

lint-go: (_install-golangci-lint GOLANGCI_LINT_VERSION GOVERSION)
    {{GOLANGCI_LINT}}_{{GOLANGCI_LINT_VERSION}}_{{GOVERSION}} run --timeout 5m

editor-config: (_install-editorconfig-checker EDITORCONFIG_CHECKER_VERSION GOVERSION)
    {{EDITORCONFIG_CHECKER}}_{{EDITORCONFIG_CHECKER_VERSION}}_{{GOVERSION}} --exclude LICENSE

license-check: (_install-licensei LICENSEI_VERSION GOVERSION)
    {{LICENSEI}}_{{LICENSEI_VERSION}}_{{GOVERSION}} check
    {{LICENSEI}}_{{LICENSEI_VERSION}}_{{GOVERSION}} header

license-cache: (_install-licensei LICENSEI_VERSION GOVERSION)
    {{LICENSEI}}_{{LICENSEI_VERSION}}_{{GOVERSION}} cache

[private]
_install-golangci-lint version goversion: _bin
    #!/usr/bin/env bash
    set -euo pipefail
    binary="{{GOLANGCI_LINT}}_${version}_${goversion}"
    if [ ! -f "$binary" ]; then
        echo "Installing golangci-lint v${version} for Go ${goversion}..."
        GOBIN=$(pwd)/{{BIN}} go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v${version}
        mv {{GOLANGCI_LINT}} "$binary"
    fi

[private]
_install-editorconfig-checker version goversion: _bin
    #!/usr/bin/env bash
    set -euo pipefail
    binary="{{EDITORCONFIG_CHECKER}}_${version}_${goversion}"
    if [ ! -f "$binary" ]; then
        echo "Installing editorconfig-checker v${version} for Go ${goversion}..."
        GOBIN=$(pwd)/{{BIN}} go install github.com/editorconfig-checker/editorconfig-checker/v3/cmd/editorconfig-checker@v${version}
        mv {{EDITORCONFIG_CHECKER}} "$binary"
    fi

[private]
_install-licensei version goversion: _bin
    #!/usr/bin/env bash
    set -euo pipefail
    binary="{{LICENSEI}}_${version}_${goversion}"
    if [ ! -f "$binary" ]; then
        echo "Installing licensei v${version} for Go ${goversion}..."
        GOBIN=$(pwd)/{{BIN}} go install github.com/goph/licensei/cmd/licensei@v${version}
        mv {{LICENSEI}} "$binary"
    fi

[private]
_bin:
    @mkdir -p {{BIN}}
