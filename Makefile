build: .bin/server

.bin/server: go.mod
	@printf \\e[1m"build server..."\\e[0m\\n
	@cd ./server && go build -o ../bin/server .
	@printf \\e[1m"build done"\\e[0m\\n

clean:
	go clean
	rm ./bin/server

test:
	go test ./...

test_coverage:
	go test ./... -coverprofile=coverage.out

dep:
	go mod download

vet:
	go vet

lint:
	golangci-lint run
