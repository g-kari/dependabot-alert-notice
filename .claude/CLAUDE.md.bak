# CLAUDE.md - dependabot-alert-notice

## プロジェクト概要

GitHub Dependabotアラートを定期ポーリングし、`claude -p` でAI評価 → Slack通知 → ボタン承認でPR自動マージを行うGoアプリケーション。

## 技術スタック

- Go 1.26+
- 外部依存: `github.com/slack-go/slack`, `gopkg.in/yaml.v3`
- CLI連携: `gh` (GitHub CLI), `claude` (Claude Code CLI)

## ディレクトリ構成

```
internal/
├── model/      # 共有データ型
├── config/     # YAML設定 + 環境変数
├── store/      # in-memory store (sync.RWMutex)
├── github/     # gh api でアラート取得
├── evaluator/  # claude -p でAI評価
├── slack/      # Socket Mode + Block Kit通知
├── web/        # HTTPサーバー + html/template
└── merger/     # gh pr merge 実行
```

## 開発コマンド

```bash
eval "$(devbox shellenv)"   # Go環境有効化
go build ./...              # ビルド
go test ./... -v -race      # テスト
go vet ./...                # 静的解析
make build-evaluator-image  # Docker評価イメージビルド
go run . -once              # 1回実行
go run . -version           # バージョン表示
```

## 設定

- `config.yaml` に設定を記述（`config.yaml.example` を参照）
- `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN` は環境変数で設定
