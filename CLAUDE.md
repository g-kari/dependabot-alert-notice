# CLAUDE.md - dependabot-alert-notice

## プロジェクト概要

GitHub Dependabotアラートを定期ポーリングし、`claude -p` でAI評価 → Slack通知 → ボタン承認でPR自動マージを行うGoアプリケーション。

## 技術スタック

- Go 1.26+（devbox管理）
- 外部依存: `github.com/slack-go/slack`, `gopkg.in/yaml.v3`
- CLI連携: `gh` (GitHub CLI), `claude` (Claude Code CLI)
- タスクランナー: `just`（`justfile` 参照）

## プロジェクト構成

```
dependabot-alert-notice/
├── main.go                  # エントリポイント（ポーリングループ・WebUI起動）
├── config.yaml.example      # 設定ファイルのテンプレート
├── tunnel.yml.example       # Cloudflare Tunnel設定テンプレート
├── Dockerfile.evaluator     # claude -p 実行用 Docker イメージ
├── justfile                 # タスクランナー（build/test/lint/run/tunnel等）
├── devbox.json              # Go環境定義
└── internal/
    ├── model/      # 共有データ型（Alert, AlertRecord, LogEntry）
    ├── config/     # YAML設定ロード/セーブ + 環境変数オーバーライド
    ├── store/      # in-memory ストア（sync.RWMutex）
    ├── github/     # gh api でDependabotアラート取得
    ├── evaluator/  # claude -p でAI評価（Docker sandbox対応）
    ├── slack/      # Socket Mode受信 + Block Kit通知
    ├── web/        # HTTP WebUI（html/template + embed.FS）
    │   └── templates/  # レイアウト + 各ページHTML
    └── merger/     # gh pr merge 実行（Interface定義済み）
```
