# dependabot-alert-notice

GitHub Dependabotアラートを定期ポーリングし、`claude -p` でAI評価 → Slack通知 → ボタン承認でPR自動マージを行うGoアプリケーション。

## フロー

```mermaid
sequenceDiagram
    participant GH as GitHub API
    participant App as dependabot-alert-notice
    participant Claude as claude -p (Docker)
    participant Slack as Slack (Socket Mode)
    participant User as オペレーター
    participant Web as WebUI :8080

    loop poll_interval ごと
        App->>GH: GET /repos/{owner}/{repo}/dependabot/alerts
        GH-->>App: []Alert (open)
        App->>App: 新規アラートのみフィルタ

        App->>Claude: docker run claude -p "{アラート情報}"
        Claude-->>App: {"risk","impact","recommendation","reasoning"}

        App->>App: store.Save(AlertRecord)

        App->>Slack: Block Kit メッセージ送信
        Slack-->>User: 通知表示
    end

    alt Slack から承認
        User->>Slack: ✅ マージ承認 ボタン
        Slack->>App: Socket Mode イベント
        App->>GH: gh pr merge --squash --auto
        GH-->>App: マージ完了
        App->>Slack: スレッドリプライ「マージしました」
    else Slack から却下
        User->>Slack: ❌ 却下 ボタン
        Slack->>App: Socket Mode イベント
        App->>App: store.UpdateState(rejected)
    end

    alt WebUI から操作
        User->>Web: GET /
        Web-->>User: アラート一覧
        User->>Web: POST /alerts/{id}/approve
        Web->>GH: gh pr merge
    end
```

## アーキテクチャ

```mermaid
graph TB
    subgraph ポーリングループ
        Ticker["time.Ticker\n(poll_interval)"]
        Ticker --> FetchAlerts
        FetchAlerts["github.Client\nFetchAlerts()"] --> Filter["新規アラート\nフィルタ"]
        Filter --> Evaluator["evaluator.Evaluate()\nclaude -p"]
        Evaluator --> Store["store.Save()\nin-memory"]
    end

    subgraph Slack通知
        Store --> Notify["slack.Notify()\nBlock Kit"]
        Notify --> SlackChannel["Slack チャンネル"]
        SlackChannel --> SocketMode["Socket Mode\nインタラクション"]
        SocketMode --> Merger["merger.Merge()\ngh pr merge"]
    end

    subgraph WebUI :8080
        Web["web.Server\nhttp.ServeMux"]
        Web --> Dashboard["GET /\nダッシュボード"]
        Web --> Detail["GET /alerts/{id}\n詳細"]
        Web --> Approve["POST /alerts/{id}/approve"]
        Web --> Reject["POST /alerts/{id}/reject"]
        Web --> Logs["GET /logs"]
        Approve --> Merger
        Reject --> StoreReject["store.UpdateState\n(rejected)"]
    end

    subgraph Dockerサンドボックス
        Evaluator --> DockerRun["docker run\n--read-only\n--cap-drop=ALL\n--no-new-privileges"]
        DockerRun --> ClaudeCLI["claude -p\n(認証情報のみ\nread-only mount)"]
    end

    Store --> Web
    Merger --> Store
```

## セキュリティ: claude -p のDocker隔離

Dependabotアラートのパッケージ名・CVE説明文にプロンプトインジェクションが仕込まれる可能性があるため、`claude -p` を専用コンテナで実行する。

```mermaid
graph LR
    subgraph ホスト
        App["dependabot-alert-notice"]
        Secrets["GITHUB_TOKEN\nSLACK_BOT_TOKEN\nSLACK_APP_TOKEN"]
        ClaudeHome["~/.claude\n(認証情報)"]
    end

    subgraph Dockerコンテナ read-only
        ClaudeCLI["claude -p"]
        TmpFS["/tmp のみ書き込み可"]
    end

    App -->|"プロンプト文字列のみ渡す"| ClaudeCLI
    ClaudeHome -->|"read-only mount"| ClaudeCLI
    Secrets -.->|"一切渡さない"| ClaudeCLI
    ClaudeCLI -->|"JSON評価結果のみ返す"| App
```

**隔離の効果:**
- ホストの `GITHUB_TOKEN` / `SLACK_*` トークンへアクセス不可
- ホストファイルシステムへの書き込み不可（`--read-only`）
- 全 Linux capability を削除（`--cap-drop=ALL`）
- メモリ 512MB / CPU 0.5 コア制限

## WebUI

```mermaid
graph TD
    A["/ ダッシュボード"] -->|"クリック"| B["GET /alerts/{id} 詳細"]
    A -->|"ナビ"| E["GET /logs ログ一覧"]

    B -->|"✅ マージ承認"| C["POST /alerts/{id}/approve\n→ gh pr merge\n→ リダイレクト /"]
    B -->|"❌ 却下"| D["POST /alerts/{id}/reject\n→ store.UpdateState\n→ リダイレクト /"]
```

### ダッシュボード (`/`)

| カラム | 内容 |
|---|---|
| ID | アラートID（詳細ページへのリンク） |
| パッケージ | 影響パッケージ名 |
| リポジトリ | `owner/repo` |
| 重要度 | critical / high / medium / low バッジ |
| CVE | CVE-XXXX-XXXXX |
| AI評価 | approve / reject / manual-review バッジ |
| ステータス | pending / approved / rejected / merged バッジ |
| 操作 | 承認・却下ボタン（pending のみ表示） |

### 詳細ページ (`/alerts/{id}`)

- アラート全情報（パッケージ、エコシステム、CVSS、概要、修正バージョン）
- AI評価（リスク、推奨、影響、理由）
- 承認・却下ボタン

### ログページ (`/logs`)

- ポーリング・AI評価・マージ操作のログを新しい順で表示

## セットアップ

### 1. 設定ファイル作成

```bash
cp config.yaml.example config.yaml
# config.yaml を編集
```

```yaml
poll_interval: 30m
targets:
  - owner: your-org
    repo: your-repo
slack:
  channel_id: C0123456789
```

```bash
export SLACK_BOT_TOKEN=xoxb-...
export SLACK_APP_TOKEN=xapp-...
```

### 2. Dockerイメージビルド（claude -p 隔離用）

```bash
eval "$(devbox shellenv)"
make build-evaluator-image
```

### 3. 実行

```bash
# 1回だけ実行（テスト）
go run . -once -config config.yaml

# 常駐実行
go run . -config config.yaml

# WebUI: http://localhost:8080
```

## Slack アプリ設定

Slack アプリに以下の設定が必要:

- **Socket Mode**: 有効
- **Bot Token Scopes**: `chat:write`, `chat:write.public`
- **Interactivity**: 有効（Socket Mode使用のためRequest URLは不要）

## 設定リファレンス

| キー | デフォルト | 説明 |
|---|---|---|
| `poll_interval` | `30m` | ポーリング間隔 |
| `targets[].owner` | 必須 | GitHubオーナー名 |
| `targets[].repo` | 省略可 | リポジトリ名（省略でorg全体） |
| `slack.channel_id` | 必須 | 通知先チャンネルID |
| `claude_path` | `claude` | claude CLIパス |
| `gh_path` | `gh` | gh CLIパス |
| `log_level` | `info` | ログレベル |
| `web.port` | `8080` | WebUIポート |
| `evaluator.sandbox.enabled` | `true` | Docker隔離の有効/無効 |

## 開発

```bash
eval "$(devbox shellenv)"   # Go環境有効化（devbox必須）
go build ./...              # ビルド
go test ./... -v -race      # テスト（全パッケージ）
go vet ./...                # 静的解析
```
