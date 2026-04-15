# =============================================================================
# Stage 1: Generate BPF objects + protobuf, then build Go binaries
# =============================================================================
FROM golang:1.23-bookworm AS builder

# Install BPF toolchain and protobuf compiler
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang llvm libbpf-dev linux-headers-amd64 \
        linux-libc-dev gcc-multilib \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

# Install Go code-gen tools (pin versions compatible with Go 1.23)
RUN go install github.com/cilium/ebpf/cmd/bpf2go@v0.17.3 \
    && go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.3 \
    && go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1

COPY . .

# Generate BPF Go bindings
RUN cd internal/ebpf && go generate ./...

# Generate protobuf Go code
RUN protoc --go_out=. --go_opt=paths=source_relative \
        --go-grpc_out=. --go-grpc_opt=paths=source_relative \
        api/v1/lb.proto

# Build static binaries
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/lbserver ./cmd/lbserver \
    && CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/lbctl ./cmd/lbctl

# =============================================================================
# Stage 2: Minimal runtime image
# =============================================================================
FROM debian:bookworm-slim

# XDP programs need: iproute2 for link info, and CAP_NET_ADMIN + CAP_BPF at runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/lbserver /usr/local/bin/lbserver
COPY --from=builder /out/lbctl   /usr/local/bin/lbctl
COPY config.example.yaml /etc/fload-balancer/config.yaml

EXPOSE 50051 8080

ENTRYPOINT ["lbserver"]
CMD ["-config", "/etc/fload-balancer/config.yaml"]
