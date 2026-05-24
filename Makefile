BINARY=vps-guard
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "0.2.0")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS=-ldflags="-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"
PREFIX=/usr/local
CONFIG_DIR=/etc/vps-guard
SYSTEMD_DIR=/etc/systemd/system
DESTDIR=

.PHONY: all build clean install uninstall test lint cross-build release

all: build

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/vps-guard

build-race:
	go build -race $(LDFLAGS) -o $(BINARY) ./cmd/vps-guard

install: build
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)$(CONFIG_DIR)
	mkdir -p $(DESTDIR)/var/log/vps-guard
	mkdir -p $(DESTDIR)/var/cache/vps-guard
	cp $(BINARY) $(DESTDIR)$(PREFIX)/bin/
	cp config.yaml $(DESTDIR)$(CONFIG_DIR)/
	cp deploy/vps-guard.service $(DESTDIR)$(SYSTEMD_DIR)/
	cp deploy/vps-guard.logrotate $(DESTDIR)/etc/logrotate.d/vps-guard
	chmod 600 $(DESTDIR)$(CONFIG_DIR)/config.yaml
	systemctl daemon-reload 2>/dev/null || true
	systemctl enable vps-guard 2>/dev/null || true
	systemctl start vps-guard 2>/dev/null || true

uninstall:
	systemctl stop vps-guard 2>/dev/null || true
	systemctl disable vps-guard 2>/dev/null || true
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	rm -f $(DESTDIR)$(SYSTEMD_DIR)/vps-guard.service
	rm -f $(DESTDIR)/etc/logrotate.d/vps-guard
	systemctl daemon-reload 2>/dev/null || true

test:
	go test -v -count=1 -race ./...

test-short:
	go test -count=1 ./...

lint:
	go vet ./...

clean:
	rm -f $(BINARY)
	rm -rf dist/

# Cross-compilation targets
cross-build: cross-amd64 cross-arm64 cross-arm

cross-amd64:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64 ./cmd/vps-guard

cross-arm64:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-arm64 ./cmd/vps-guard

cross-arm:
	GOOS=linux GOARCH=arm go build $(LDFLAGS) -o dist/$(BINARY)-linux-arm ./cmd/vps-guard

# Release: cross-build + checksum
release: cross-build
	cd dist && sha256sum $(BINARY)-linux-* > checksums.txt
	@echo ""
	@echo "Release $(VERSION) ready in dist/:"
	@ls -lh dist/

# Check: run tests + lint + build
check: test lint build
	@echo "All checks passed ✓"
