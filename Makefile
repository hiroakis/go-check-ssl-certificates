.PHONY: all clean deps test build

all: clean deps test build

deps:
	go get -u github.com/stretchr/testify/assert

test:
	go test -v

build: deps test
	GOARCH=386 go build -ldflags="-s -w" -o go-check-ssl-certificates cmd/*.go

clean:
	rm -rf go-check-ssl-certificates

