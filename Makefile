# GHOST — build & dev tasks
#
# Usage:
#   make            # build all binaries (default)
#   make build      # same
#   make test       # run unit tests
#   make vet        # go vet
#   make tidy       # go mod tidy
#   make clean      # remove build artifacts
#   make capture    # placeholder for traffic capture (Phase 6)

BIN_DIR := bin
GO      := go
GOFLAGS := -trimpath
LDFLAGS := -s -w

BINARIES := ghost-server ghost-client ghost-tools

.PHONY: all build $(BINARIES) test vet tidy clean capture check check-remote

all: build

build: $(BINARIES)

$(BINARIES):
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/$@ ./cmd/$@

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

clean:
	rm -rf $(BIN_DIR)

capture:
	@echo "capture: not implemented yet (Phase 6)"
	@exit 1

# Run security & functionality checks locally (requires active ghost-client).
check:
	@bash test/check.sh

# Run full self-test suite on the server via SSH (no local root needed).
# Uploads client binary, starts it in loopback mode, tests everything, cleans up.
check-remote: ghost-client
	@bash test/remote_check.sh $(SERVER_IP)
