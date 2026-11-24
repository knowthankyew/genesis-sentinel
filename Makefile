.PHONY: all build test race lint fmt clean

all: build

build:
	@mkdir -p bin
	go build -o bin/sentinel ./cmd/sentinel

test:
	go test -v ./...

race:
	go test -v -race ./...

lint:
	go vet ./...
	@if command -v staticcheck >/dev/null 2>&1; then \
		echo "Running staticcheck..."; \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed, skipping (install with: go install honnef.co/go/tools/cmd/staticcheck@latest)"; \
	fi

fmt:
	gofmt -s -w .

clean:
	rm -rf bin/
