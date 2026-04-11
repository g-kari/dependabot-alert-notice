# TDD（テスト駆動開発）方針

## 基本ルール

- **新機能・バグ修正は必ずテストを先に書く**
- テストが失敗することを確認してから実装する（Red → Green → Refactor）
- テストなしのコードはコミットしない

## テスト配置

- 各パッケージと同じディレクトリに `_test.go` を置く
- パッケージ名は `package xxx_test` ではなく `package xxx`（ホワイトボックステスト）

## モック方針

- 外部コマンド（`gh`, `claude`）はインターフェース経由でモックする
- `github.Client`, `evaluator.Evaluator`, `merger.Interface` はすべてインターフェース定義済み
- `web.Server` のテストは `httptest.NewRecorder()` を使う
- Slack SDK の依存はnilガードで吸収する

## 実行コマンド

```bash
just test          # go test ./... -v -race -count=1
go test ./...      # 全パッケージ
go test ./internal/web/... -run TestSettings  # 特定のテスト
```

## カバレッジ確認

```bash
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out
```
