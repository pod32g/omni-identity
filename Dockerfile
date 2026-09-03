# Build stage. Pinned to the exact patch in go.mod so no toolchain is downloaded.
FROM golang:1.26.8-bookworm@sha256:9fdc884aacc3bec89b20ffc69f4bb369c78210e3e4f600387b5128b12c199f81 AS build
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
# Endpoint artifacts served on the "Enroll a device" page: the omni-enrollment
# agent for Linux (pure Go, no CGO) and the PAM/systemd sources, all built from
# the same commit as the server so versions always match.
RUN mkdir /downloads \
    && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.version=docker" -o /downloads/omni-enrollment-linux-amd64 ./cmd/omni-enrollment \
    && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "-X main.version=docker" -o /downloads/omni-enrollment-linux-arm64 ./cmd/omni-enrollment \
    && tar -czf /downloads/omni-enrollment-endpoint.tar.gz endpoint/pam endpoint/systemd

# Runtime stage: distroless with glibc (the CGO binary is dynamically linked
# against libc), running as the non-root distroless user (65532).
FROM gcr.io/distroless/base-debian12:nonroot@sha256:4ae8d0163a6f04d96f36e41324d76f00744f0db7545b6d04039c9e6fa1df77f3
COPY --from=build --chown=65532:65532 /omni-identity /omni-identity
COPY --from=build --chown=65532:65532 /data /data
COPY --from=build --chown=65532:65532 /downloads /downloads
USER 65532:65532
EXPOSE 8080
VOLUME ["/data"]
ENTRYPOINT ["/omni-identity"]
CMD ["serve"]
