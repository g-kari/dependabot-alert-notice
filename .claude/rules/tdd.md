# TDD（テスト駆動開発）方針

**このルールはGoコードを書くすべての作業に適用する。**

## 絶対ルール

- **実装より先にテストを書く** — 例外なし
- Red → Green → Refactor サイクルを守る
- テストが失敗することを確認してから実装に入る
- テストなしのGoコードはコミットしない

## テスト作成の手順

1. `_test.go` ファイルに期待する振る舞いをテストとして書く
2. `just test` を実行してRedになることを確認する
3. テストを通す最小限の実装を書く
4. `just test` でGreenになることを確認する
5. リファクタリングして再度Greenを確認する

## テスト配置

- 各パッケージと同じディレクトリに `_test.go` を置く
- パッケージ名は `package xxx`（ホワイトボックステスト）

## モック方針

- 外部コマンド（`gh`, `claude`）はインターフェース経由でモックする
- `github.Client`, `evaluator.Evaluator`, `merger.Interface` はすべてインターフェース定義済み
- `web.Server` のテストは `httptest.NewRecorder()` を使う
- Slack SDK の依存はnilガードで吸収する

## 実行コマンド

```bash
just test                                              # 全テスト（-v -race -count=1）
go test ./internal/xxx/... -run TestFuncName -v       # 特定テストのみ
go test ./... -coverprofile=coverage.out && go tool cover -html=coverage.out  # カバレッジ
```
