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

TUNNEL_NAME := "dependabot-alert-notice"
TUNNEL_HOSTNAME := "security.0g0.xyz"

# 初回セットアップ: ログイン→トンネル作成→DNS登録→tunnel.yml生成
tunnel-setup:
    cloudflared login
    cloudflared tunnel create {{TUNNEL_NAME}}
    cloudflared tunnel route dns {{TUNNEL_NAME}} {{TUNNEL_HOSTNAME}}
    @echo ""
    @echo "tunnel.yml を作成してください:"
    @echo "  cp tunnel.yml.example tunnel.yml"
    @echo "  # TUNNEL_ID と USER を書き換える"
    @echo "  cloudflared tunnel list  # TUNNEL_IDを確認"

# トンネル実行（tunnel.yml が必要）
tunnel:
    cloudflared tunnel --config tunnel.yml run {{TUNNEL_NAME}}

# クイックトンネル（一時URL・設定不要）
tunnel-quick:
    cloudflared tunnel --url http://localhost:8999

install-hooks:
    pre-commit install

# Go依存関係を最新に更新してテストを通す
update:
    go get -u ./...
    go mod tidy
    go test ./... -count=1 -race
