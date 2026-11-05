# Claude Code compatibility

開発ルールの正本は `AGENTS.md` です。作業開始時にルートの `AGENTS.md` を読み、対象ディレクトリにある階層別 `AGENTS.md` も適用してください。

- 全体方針、TDD、Git、開発コマンド: `AGENTS.md`
- Go 実装品質: `internal/AGENTS.md`
- Web UI と HTML: `internal/web/AGENTS.md`

`.claude/rules/` は既存 Claude Code 環境との互換性のため残しています。ルールが競合する場合は、上記 `AGENTS.md` を正とします。
