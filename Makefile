SHELL := /bin/sh

SWIFT ?= swift
CODESIGN ?= codesign
STRIP ?= strip
CONFIGURATION ?= release
PREFIX ?= $(HOME)/.local
DESTDIR ?=
BINARY := keychain-api
CODESIGN_IDENTITY ?= -
CODESIGN_IDENTIFIER ?= local.keychain-api

.PHONY: build debug release test version sign verify dist install clean

build:
	$(SWIFT) build --configuration $(CONFIGURATION)

debug:
	$(MAKE) build CONFIGURATION=debug

release:
	$(MAKE) build CONFIGURATION=release

test:
	$(SWIFT) run --configuration $(CONFIGURATION) $(BINARY) self-test

version:
	@$(SWIFT) run --configuration $(CONFIGURATION) $(BINARY) --version

sign: release
	$(STRIP) -S -x "$$($(SWIFT) build --configuration release --show-bin-path)/$(BINARY)"
	$(CODESIGN) --force --sign "$(CODESIGN_IDENTITY)" --options runtime --identifier "$(CODESIGN_IDENTIFIER)" "$$($(SWIFT) build --configuration release --show-bin-path)/$(BINARY)"

verify: sign
	$(CODESIGN) --verify --strict --verbose=2 "$$($(SWIFT) build --configuration release --show-bin-path)/$(BINARY)"

dist: verify
	./scripts/package-release.sh "$$($(SWIFT) build --configuration release --show-bin-path)/$(BINARY)"

install: verify
	install -d -m 0700 "$(DESTDIR)$(PREFIX)/bin"
	install -m 0700 "$$($(SWIFT) build --configuration release --show-bin-path)/$(BINARY)" "$(DESTDIR)$(PREFIX)/bin/$(BINARY)"

clean:
	$(SWIFT) package clean
