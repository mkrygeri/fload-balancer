.PHONY: all generate build proto bpf clean install-deps docker install uninstall

CLANG   ?= clang
CFLAGS  := -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86
GO      := go
PROTOC  := protoc
BINARY_SERVER := bin/lbserver
BINARY_CLI    := bin/lbctl

all: generate build

# Install required build tools
install-deps:
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate BPF objects and protobuf code
generate: bpf proto

# Generate BPF Go bindings
bpf:
	cd internal/ebpf && $(GO) generate ./...

# Generate protobuf Go code
proto:
	$(PROTOC) --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/v1/lb.proto

# Build Go binaries
build:
	CGO_ENABLED=0 $(GO) build -o $(BINARY_SERVER) ./cmd/lbserver
	CGO_ENABLED=0 $(GO) build -o $(BINARY_CLI) ./cmd/lbctl

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f internal/ebpf/xdplb_bpf*.go internal/ebpf/xdplb_bpf*.o
	rm -f api/v1/*.pb.go

# Run tests
test:
	$(GO) test ./...

# Docker build
docker:
	docker build -t fload-balancer:latest .

# systemd install / uninstall (run as root)
install:
	./deploy/install.sh install

uninstall:
	./deploy/install.sh uninstall

# Format
fmt:
	$(GO) fmt ./...
	$(CLANG) -i bpf/*.c bpf/*.h 2>/dev/null || true
