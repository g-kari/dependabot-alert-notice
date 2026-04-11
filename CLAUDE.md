# CLAUDE.md - dependabot-alert-notice

## プロジェクト概要

GitHub Dependabotアラートを定期ポーリングし、`claude -p` でAI評価 → Slack/Discord通知 → ボタン承認でPR自動マージを行うGoアプリケーション。

## 技術スタック

- Go 1.26+（devbox管理）
- 外部依存: `github.com/slack-go/slack`, `gopkg.in/yaml.v3`, `modernc.org/sqlite`
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
    ├── store/      # SQLiteストア（modernc.org/sqlite）
    ├── queue/      # JobQueue（Worker Pool、FetchAlerts/EvaluateAlertジョブ）
    ├── github/     # gh api でDependabotアラート取得（REST + GraphQL）
    ├── evaluator/  # claude -p でAI評価（Docker sandbox対応）
    ├── slack/      # Socket Mode受信 + Block Kit通知
    ├── discord/    # Webhook通知
    ├── web/        # HTTP WebUI（html/template + embed.FS）
    │   └── templates/  # レイアウト + 各ページHTML
    └── merger/     # gh pr merge 実行（Interface定義済み）
```

## 開発コマンド

```bash
eval "$(devbox shellenv)"   # Go環境有効化
just test                   # テスト（go test ./... -v -race -count=1）
just build                  # ビルド
just lint                   # go vet ./...
just run                    # アプリ起動
go test ./internal/web/... -run TestXxx  # 特定テストのみ
```

## 開発方針（必須）

### TDD: テストを先に書く

**新機能・バグ修正は必ずテストを先に書いてから実装する。**

1. テスト作成（Red: 失敗することを確認）
2. 実装（Green: テストを通す最小限の実装）
3. リファクタリング（Refactor: 品質改善）

テストなしのGoコードはコミットしない。詳細は `.claude/rules/tdd.md` 参照。

### インターフェース設計

外部コマンド（`gh`, `claude`）・外部サービス（Slack）はインターフェース経由でモック可能にする。
`github.Client`, `evaluator.Evaluator`, `merger.Interface` はすべてインターフェース定義済み。
