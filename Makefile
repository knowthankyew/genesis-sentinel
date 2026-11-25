.PHONY: all build bench test race lint fmt audit sbom claims-test clean

all: build

build:
	@mkdir -p bin
	go build -o bin/sentinel ./cmd/sentinel
	go build -o bin/sentinel-bench ./cmd/sentinel-bench

bench: build
	./bin/sentinel-bench --lines 100000 --out-json docs/benchmarks/empirical_benchmarks.json --out-md auto

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

sbom:
	python3 ./scripts/generate-sbom.py bom.json

claims-test:
	python3 -m unittest discover -s tests

audit:
	python3 ./scripts/audit-claims.py

clean:
	rm -rf bin/
