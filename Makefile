VERSION ?= 0.2.0

.PHONY: build test release clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o easessh .

test:
	go vet ./...
	go test -count=1 ./...

release:
	scripts/release.sh $(VERSION)

clean:
	rm -rf dist easessh
