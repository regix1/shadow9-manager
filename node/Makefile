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
GO_TOOLCHAIN := go1.21.13
DIST ?= dist
VERSION_FILE := $(dir $(lastword $(MAKEFILE_LIST)))../VERSION
ifeq ($(origin VERSION), undefined)
ifeq ($(wildcard $(VERSION_FILE)),)
$(error missing $(VERSION_FILE))
endif
VERSION := $(strip $(shell cat $(VERSION_FILE)))
ifeq ($(VERSION),)
$(error $(VERSION_FILE) is empty)
endif
endif
BINARY := shadow9-node

TARGETS := linux-amd64 linux-arm64 linux-mipsle
BINARIES := $(addprefix $(DIST)/$(BINARY)-,$(TARGETS))
CHECKSUMS := $(DIST)/SHA256SUMS

# $(wildcard) rather than a shell call to find: on Windows "find" resolves to
# FIND.EXE, which fails and leaves this empty, and an empty prerequisite list
# means an edited source file never triggers a rebuild.
GO_SOURCES := $(wildcard *.go) $(wildcard internal/*/*.go)
# VERSION is a prerequisite because it is linked into the binary. Without it,
# bumping the version and rebuilding leaves the old string baked in and every
# artifact quietly reports the previous release, which is the exact fault this
# file's version handling exists to prevent. $(wildcard) so an overriding
# VERSION= on the command line still works when the file is absent.
SOURCES := $(filter-out %_test.go,$(GO_SOURCES)) $(wildcard internal/*/*.json) go.mod \
	$(wildcard $(VERSION_FILE))

# GOTOOLCHAIN selects the exact compiler named in go.mod. With that input fixed,
# -trimpath removes build-directory names, -buildvcs=false keeps local git state
# out, and -buildid= removes the last machine-specific value. The same commit,
# version and target then produce byte-identical binaries on different machines.
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
		GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) build $(BUILD_FLAGS) -ldflags '$(LDFLAGS)' -o $@ .

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
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) test ./...

## vet: report suspicious constructs
vet:
	GOTOOLCHAIN=$(GO_TOOLCHAIN) $(GO) vet ./...

## check: what CI runs
check: test vet

$(CHECKSUMS): $(BINARIES)
	cd $(DIST) && sha256sum $(notdir $(BINARIES)) > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS

## checksums: record what was built, so a rebuild can be compared to it
checksums: $(CHECKSUMS)

clean:
	rm -rf $(DIST)
