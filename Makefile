BINARY := omni-identity
PKG := ./cmd/omni-identity
# CGO is required by the SQLite driver (mattn/go-sqlite3).
export CGO_ENABLED := 1

.PHONY: build test vet run tidy clean

build:
	go build -o $(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

run: build
	./$(BINARY) -config config.yaml

tidy:
	go mod tidy

clean:
	rm -f $(BINARY)
	rm -f *.db *.db-wal *.db-shm
