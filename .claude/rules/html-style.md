---
paths:
  - "**/*.html"
---

# HTML テンプレート コーディング規約

## デザインシステム

- **カラーパレット**: CSS 変数（`--color-bg`, `--color-text`, `--color-muted`, `--color-border`, `--color-surface`, `--color-accent`, `--color-danger`）を使用する
- **フォント**: `var(--font)` 経由で Reddit Sans + IBM Plex Sans JP が適用される
- **アニメーション**: ホバーエフェクトは `.interactive-scale` / `.interactive-scale-sm` クラスを使う

## 禁止事項: inline style の使用禁止

`style="..."` 属性での装飾は原則禁止。以下の代替手段を使う：

| やりたいこと | 使うべき手段 |
|---|---|
| 背景色・文字色 | CSS 変数 + layout.html の `<style>` にクラス追加 |
| 余白・配置 | layout.html のユーティリティクラス or クラス追加 |
| ボタン | `.btn`, `.btn-approve`, `.btn-reject`, `.btn-ghost`, `.btn-primary` |
| カード | `.card` |
| テーブル | `.table-wrap > table` 構造 |
| バッジ | `.badge .badge-{critical|high|medium|low|pending|approved|rejected|merged|info|error|warn}` |
| メッセージ | `.msg .msg-error` / `.msg .msg-success` |
| ログ | `.log-entry`, `.log-ts`, `.log-msg` |

## 例外

構造上どうしても必要な場合（`width` の個別指定など）は最小限に留める。その場合も色・背景・フォントは CSS 変数で参照する。

```html
<!-- NG -->
<div style="color:#8b949e;background:#161b22;padding:10px">

<!-- OK: クラスを使う -->
<div class="card">

<!-- OK: width のみ（色・背景なし）-->
<input type="text" style="width:180px">
```

## コンポーネントクラス一覧（layout.html 定義済み）

- `.card` — ボーダー付きカード
- `.btn`, `.btn-primary`, `.btn-approve`, `.btn-reject`, `.btn-ghost` — ボタン
- `.badge`, `.badge-{variant}` — バッジ
- `.table-wrap` — テーブルのスクロールラッパー
- `.field` — フォームフィールド（label + input）
- `.msg`, `.msg-error`, `.msg-success` — フラッシュメッセージ
- `.log-entry`, `.log-ts`, `.log-msg` — ログ行
- `.nav-link` — ヘッダーナビリンク
- `.interactive-scale`, `.interactive-scale-sm` — ホバースケールエフェクト
