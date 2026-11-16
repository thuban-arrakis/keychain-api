SHELL := /bin/sh

SWIFT ?= swift
CODESIGN ?= codesign
CONFIGURATION ?= release
PREFIX ?= $(HOME)/.local
DESTDIR ?=
BINARY := keychain-api
CODESIGN_IDENTITY ?= -
CODESIGN_IDENTIFIER ?= local.keychain-api

.PHONY: build debug release test sign verify install clean

build:
	$(SWIFT) build --configuration $(CONFIGURATION)

debug:
	$(MAKE) build CONFIGURATION=debug

release:
	$(MAKE) build CONFIGURATION=release

test:
	$(SWIFT) run $(BINARY) self-test

sign: release
	$(CODESIGN) --force --sign "$(CODESIGN_IDENTITY)" --options runtime --identifier "$(CODESIGN_IDENTIFIER)" "$$($(SWIFT) build --configuration release --show-bin-path)/$(BINARY)"

verify: sign
	$(CODESIGN) --verify --strict --verbose=2 "$$($(SWIFT) build --configuration release --show-bin-path)/$(BINARY)"

install: verify
	install -d -m 0700 "$(DESTDIR)$(PREFIX)/bin"
	install -m 0700 "$$($(SWIFT) build --configuration release --show-bin-path)/$(BINARY)" "$(DESTDIR)$(PREFIX)/bin/$(BINARY)"

clean:
	$(SWIFT) package clean
