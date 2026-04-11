---
paths:
  - "**/*.go"
---

# Go コーディング規約

## 静的解析

- `go vet ./...` を編集後に必ず実行
- `just lint` でまとめて実行可能

## エラーハンドリング

```go
// ラップして文脈を付与する
return fmt.Errorf("fetchAlerts: %w", err)

// エラーを無視しない（_ = err は禁止）
if err := something(); err != nil {
    return fmt.Errorf("something: %w", err)
}
```

## ロギング

- `log/slog` を使用（`fmt.Println` や `log.Printf` は使わない）
- 構造化ログを心がける

```go
slog.Info("alert fetched", "repo", repo, "count", len(alerts))
slog.Error("fetch failed", "repo", repo, "err", err)
```

## 並行処理

- 共有データは `sync.RWMutex` で保護する（`store` パッケージのパターンに従う）
- goroutine を起動する際は `context.Context` を受け取って伝播する
- `go func()` の中でエラーをサイレントに捨てない

## インターフェース設計

- 外部コマンド・外部サービスは必ずインターフェース経由にする（テスト可能にするため）
- インターフェースは実装側ではなく、利用側のパッケージに定義する

```go
// 利用側（web パッケージ）でインターフェースを定義する
type GitHubClient interface {
    FetchAlerts(ctx context.Context, target config.Target) ([]model.Alert, error)
}
```

## 命名規則

- exported な型・関数はGoのドキュメント規約に従う（`// Xxx は...`）
- テスト用のモックは `Mock` プレフィックスを使う（例: `MockClient`）
- テストヘルパーは `t.Helper()` を先頭に入れる

## 外部依存

- 標準ライブラリを優先する
- 新しい外部パッケージを追加する前に、標準ライブラリで実現できないか確認する
