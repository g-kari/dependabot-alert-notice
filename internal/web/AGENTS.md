# Web UI 実装ルール

このファイルは `internal/web/` 配下に適用する。上位の `AGENTS.md` も併せて守る。

## テンプレートとデザイン

- 色、背景、フォントには `layout.html` の CSS 変数を使う。
- フォントは `var(--font)` を利用する。
- ホバー効果は `.interactive-scale` または `.interactive-scale-sm` を利用する。
- 装飾目的の inline `style` は使わず、`layout.html` に再利用可能なクラスを追加する。
- 構造上必要な個別の幅指定などは最小限の inline style を許容するが、色・背景・フォントは指定しない。

既存の主要クラス:

- カード: `.card`
- ボタン: `.btn`, `.btn-primary`, `.btn-approve`, `.btn-reject`, `.btn-ghost`
- バッジ: `.badge`, `.badge-critical`, `.badge-high`, `.badge-medium`, `.badge-low`, `.badge-pending`, `.badge-approved`, `.badge-rejected`, `.badge-merged`, `.badge-info`, `.badge-error`, `.badge-warn`
- テーブル: `.table-wrap > table`
- フォーム: `.field`
- メッセージ: `.msg`, `.msg-error`, `.msg-success`
- ログ: `.log-entry`, `.log-ts`, `.log-msg`
- ナビゲーション: `.nav-link`

## 安全性と検証

- テンプレートには `html/template` の自動エスケープを維持し、外部入力を安易に `template.HTML` に変換しない。
- POST 操作、リダイレクト、SSE の既存パターンに合わせる。
- UI 変更後は関連する `internal/web/*_test.go` とリポジトリ全体のチェックを実行する。
- JavaScript を変更する場合は、ページ再読込、sessionStorage、SSE 接続への影響を確認する。
