default: build

build:
    go build -o bin/dependabot-alert-notice .

test:
    go test ./... -v -race -count=1

vet:
    go vet ./...

lint: vet
    golangci-lint run ./...

run:
    go run . -config config.yaml

run-once:
    go run . -config config.yaml -once

build-evaluator-image:
    docker build -f Dockerfile.evaluator -t dependabot-evaluator:latest .

install-hooks:
    pre-commit install

# Go依存関係を最新に更新してテストを通す
update:
    go get -u ./...
    go mod tidy
    go test ./... -count=1 -race
