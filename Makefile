BINARY  ?= omni-identity
VERSION ?= 0.1.0-dev
PKG      = ./cmd/omni-identity
LDFLAGS  = -ldflags "-X main.version=$(VERSION)"
# CGO is required by the SQLite driver (mattn/go-sqlite3).
export CGO_ENABLED := 1

.PHONY: build test test-postgres vet fmt run tidy clean docker compose-up compose-down

## build: compile the single binary
build:
	go build $(LDFLAGS) -o $(BINARY) $(PKG)

## test: run the full test suite (SQLite backend)
test:
	go test ./...

## test-postgres: run the store integration test against an ephemeral Postgres
test-postgres:
	docker rm -f omni-pg-test >/dev/null 2>&1 || true
	docker run -d --name omni-pg-test -e POSTGRES_PASSWORD=omni -e POSTGRES_USER=omni \
		-e POSTGRES_DB=omni -p 55432:5432 postgres:16-alpine >/dev/null
	@sleep 4
	OMNI_TEST_POSTGRES_URL='postgres://omni:omni@localhost:55432/omni?sslmode=disable' \
		go test ./internal/store/ -run Postgres -v; \
		status=$$?; docker rm -f omni-pg-test >/dev/null 2>&1 || true; exit $$status

## vet: run go vet
vet:
	go vet ./...

## fmt: format all Go code
fmt:
	gofmt -w .

## run: build and start the server
run: build
	./$(BINARY) serve -config config.yaml

## tidy: tidy go modules
tidy:
	go mod tidy

## clean: remove build artifacts and local databases
clean:
	rm -f $(BINARY)
	rm -f *.db *.db-wal *.db-shm

## docker: build the container image
docker:
	docker build -t $(BINARY):$(VERSION) .

## compose-up: build and start via docker compose (uses .env)
compose-up:
	docker compose up --build -d

## compose-down: stop the compose stack
compose-down:
	docker compose down
