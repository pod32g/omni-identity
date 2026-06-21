# Build stage. Pinned to the exact patch in go.mod so no toolchain is downloaded.
FROM golang:1.26.4-bookworm@sha256:5f68ec6805843bd3981a951ffada82a26a0bd2631045c8f7dba483fa868f5ec5 AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO is required by the SQLite driver (mattn/go-sqlite3); the bookworm image
# ships gcc. Security checks run as part of the image build so CI cannot publish
# an image whose tests fail or whose reachable Go symbols have known vulns.
ENV CGO_ENABLED=1
RUN go test ./...
RUN go run golang.org/x/vuln/cmd/govulncheck@v1.3.0 ./...
RUN mkdir /data && go build -ldflags "-X main.version=docker" -o /omni-identity ./cmd/omni-identity

# Runtime stage: distroless with glibc (the CGO binary is dynamically linked
# against libc), running as the non-root distroless user (65532).
FROM gcr.io/distroless/base-debian12:nonroot@sha256:4ae8d0163a6f04d96f36e41324d76f00744f0db7545b6d04039c9e6fa1df77f3
COPY --from=build --chown=65532:65532 /omni-identity /omni-identity
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/omni-identity"]
CMD ["serve"]
