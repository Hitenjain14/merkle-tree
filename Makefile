build:
	go build -o ./bin/go-blockchain

run:build
	./bin/go-blockchain

test:
	go test -v ./...	
