.PHONY: build test vet lint run build-evaluator-image

build:
	go build -o bin/dependabot-alert-notice .

test:
	go test ./... -v -race -count=1

vet:
	go vet ./...

lint: vet
	go test ./... -count=1

run:
	go run . -config config.yaml

run-once:
	go run . -config config.yaml -once

build-evaluator-image:
	docker build -f Dockerfile.evaluator -t dependabot-evaluator:latest .
