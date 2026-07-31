# Cross-compilation for the shadow9 node client.
#
# One build per GOARCH, not per OpenWrt target. Every aarch64_cortex-a* target
# takes the same arm64 binary, because CGO_ENABLED=0 makes the binary static
# and it links no libc at all, so musl versus glibc is not a question.
#
# OpenWrt ARCH to GOARCH, from OpenWrt's own lang/golang/golang-values.mk:
#
#   x86_64       amd64
#   aarch64      arm64
#   mipsel       mipsle      GOMIPS=softfloat on soft-float targets
#   mips         mips
#   arm          arm         GOARM 5, 6 or 7 by FPU
#   mips64el     mips64le
#   riscv64      riscv64
#
# mipsle is built softfloat, which runs on both soft-float and hard-float MIPS
# routers. A hardfloat build is faster on the hardware that has an FPU and does
# not run at all on the hardware that does not, so softfloat is the one binary
# to serve when the router is unknown.

GO ?= go
DIST ?= dist
VERSION ?= 0.1.0
BINARY := shadow9-node

TARGETS := linux-amd64 linux-arm64 linux-mipsle
BINARIES := $(addprefix $(DIST)/$(BINARY)-,$(TARGETS))
CHECKSUMS := $(DIST)/SHA256SUMS

# $(wildcard) rather than a shell call to find: on Windows "find" resolves to
# FIND.EXE, which fails and leaves this empty, and an empty prerequisite list
# means an edited source file never triggers a rebuild.
GO_SOURCES := $(wildcard *.go) $(wildcard internal/*/*.go)
SOURCES := $(filter-out %_test.go,$(GO_SOURCES)) $(wildcard internal/*/*.json) go.mod

# -trimpath removes the build machine's directory names, -buildvcs=false keeps
# the git state out, and -buildid= drops the one remaining input that changes
# between otherwise identical builds. Together these make two builds of the
# same commit on two machines produce byte-identical binaries.
BUILD_FLAGS := -trimpath -buildvcs=false
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)

GOMIPS_mipsle := softfloat

.PHONY: all dist test vet check clean checksums contract

all: dist

## dist: cross-compile every target into $(DIST)
dist: $(BINARIES) $(CHECKSUMS)

$(DIST)/$(BINARY)-linux-%: $(SOURCES)
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=$* GOMIPS=$(GOMIPS_$*) \
		$(GO) build $(BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $@ .

## contract: refresh the embedded copy of the enrollment contract
#
# internal/contract holds a copy of contracts/enrollment because Go's test cache
# does not track a file outside the module, so a test that read the contract by
# path kept reporting a stale pass after it changed. Embedding makes each file a
# build input. contracts/enrollment stays the only place anyone edits, and
# tests/test_wireguard_contract.py fails if this copy falls behind it.
contract:
	cp ../contracts/enrollment/*.json internal/contract/

## test: run the Go tests, including the RFC 7748 vector and the contract
test:
	$(GO) test ./...

## vet: report suspicious constructs
vet:
	$(GO) vet ./...

## check: what CI runs
check: test vet

$(CHECKSUMS): $(BINARIES)
	cd $(DIST) && sha256sum $(notdir $(BINARIES)) > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS

## checksums: record what was built, so a rebuild can be compared to it
checksums: $(CHECKSUMS)

clean:
	rm -rf $(DIST)
