.PHONY: lint vendor clean

export GO111MODULE=on

default: lint

lint:
	golangci-lint run

vendor:
	go mod vendor

clean:
	rm -rf ./vendor
