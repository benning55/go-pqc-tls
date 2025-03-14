# Variables for flexibility
BINDIR := bin
SERVER_SRC := server/main.go
CLIENT_SRC := client/main.go
SERVER_BIN := $(BINDIR)/server
CLIENT_BIN := $(BINDIR)/client

PEER_SRC := peer/main.go
PEER_BIN := $(BINDIR)/peer

# Phony targets (not tied to files)
.PHONY: all build clean test test_coverage dep vet lint

# Default target
all: build

# Build both server and client
build: $(SERVER_BIN) $(CLIENT_BIN) $(PEER_BIN)
	@echo "\033[1mBuild completed successfully\033[0m"

# Build server
$(SERVER_BIN): $(SERVER_SRC) go.mod
	@echo "\033[1mBuilding server...\033[0m"
	@cd ./server && go build -o ../$(SERVER_BIN) .
	@chmod +x $(SERVER_BIN)

# Build client
$(CLIENT_BIN): $(CLIENT_SRC) go.mod
	@echo "\033[1mBuilding client...\033[0m"
	@cd ./client && go build -o ../$(CLIENT_BIN) .
	@chmod +x $(CLIENT_BIN)


# Build peer
$(PEER_BIN): $(PEER_SRC) go.mod
	@echo "\033[1mBuilding peer...\033[0m"
	@cd ./peer && go build -o ../$(PEER_BIN) .
	@chmod +x $(PEER_BIN)

# Clean up binaries and Go cache
clean:
	@echo "\033[1mCleaning up...\033[0m"
	@go clean
	@rm -f $(BINDIR)/*
	@echo "\033[1mClean completed\033[0m"

# Run tests
test:
	@go test ./...

# Run tests with coverage
test_coverage:
	@go test ./... -coverprofile=coverage.out
	@go tool cover -html=coverage.out -o coverage.html

# Download and tidy dependencies
dep:
	@echo "\033[1mFetching dependencies...\033[0m"
	@go mod download
	@go mod tidy

# Run Go vet
vet:
	@go vet ./...

# Run linter (requires golangci-lint)
lint:
	@golangci-lint run ./...