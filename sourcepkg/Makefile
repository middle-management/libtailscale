# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

# Construct a source package by vendoring all source and packing it up into a
# tarball.

ifeq ($(shell uname -s),Darwin)
	TAR?=gtar
else
	TAR?=tar
endif

all: check

check: libtailscale.tar.zst
	@echo "Checking that the tarball is self-contained..."
	test `$(TAR) tf libtailscale.tar.zst | grep -c -v '^libtailscale/'` -eq 0 || (echo "Tarball is not self-contained!" && exit 1)

	@tar xf libtailscale.tar.zst
	@echo "Checking that the tarball is usable..."
	@cd libtailscale && ./configure && make


clean:
	rm -rf ./libtailscale.tar.zst ../vendor ./libtailscale

# Every non-test source of the root package, plus the guest package it
# imports (same module, so vendoring never covers it).
GO_SRCS=../tailscale.go ../bridge.go ../bridge_unix.go ../bridge_windows.go ../guestnode.go
GO_PKGS=../guest

../vendor: ../go.mod ../go.sum $(GO_SRCS) Makefile.src Makefile
	go mod vendor

libtailscale.tar.zst: Makefile.src configure ../vendor ../LICENSE $(GO_SRCS) $(GO_PKGS) ../go.mod ../go.sum
	$(TAR) --transform 's#^#libtailscale/#' --transform 's#Makefile.src#Makefile#' -acf $@ Makefile.src configure ../vendor ../LICENSE $(GO_SRCS) $(GO_PKGS) ../go.mod ../go.sum