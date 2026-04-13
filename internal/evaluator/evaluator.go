package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

type Evaluator interface {
	Evaluate(ctx context.Context, alert model.Alert) (*model.Evaluation, error)
}

func New(cfg *config.Config) Evaluator {
	if cfg.Evaluator.Sandbox.Enabled {
		return &DockerEvaluator{cfg: cfg.Evaluator}
	}
	return &DirectEvaluator{claudePath: cfg.ClaudePath}
}

// DirectEvaluator はclaude CLIを直接実行する（テスト用・sandbox無効時）
type DirectEvaluator struct {
	claudePath string
}

func (e *DirectEvaluator) Evaluate(ctx context.Context, alert model.Alert) (*model.Evaluation, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	prompt := buildPrompt(alert)
	cmd := exec.CommandContext(ctx, e.claudePath, "-p", prompt, "--output-format", "json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("claude -p 実行失敗: %w", err)
	}

	return parseEvaluation(out)
}

// DockerEvaluator はDockerコンテナ内でclaude CLIを実行する（セキュリティ隔離）
type DockerEvaluator struct {
	cfg config.EvaluatorConfig
}

func (e *DockerEvaluator) Evaluate(ctx context.Context, alert model.Alert) (*model.Evaluation, error) {
	timeout := e.cfg.Sandbox.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	claudeHome := e.cfg.Sandbox.ClaudeHome
	if claudeHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("ホームディレクトリ取得失敗: %w", err)
		}
		claudeHome = home + "/.claude"
	}

	prompt := buildPrompt(alert)

	args := e.buildDockerArgs(prompt, claudeHome)
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker run claude -p 実行失敗: %w", err)
	}

	return parseEvaluation(out)
}

// buildDockerArgs はDockerコンテナ実行用のコマンド引数を生成する（テスト可能にするため分離）
func (e *DockerEvaluator) buildDockerArgs(prompt, claudeHome string) []string {
	// claudeHome は ~/.claude ディレクトリのパス。その親がホームディレクトリ
	homeDir := filepath.Dir(claudeHome)
	claudeJSON := homeDir + "/.claude.json"
	return []string{
		"run", "--rm",
		"-v", claudeHome + ":/home/node/.claude:ro",
		"-v", claudeJSON + ":/home/node/.claude.json:ro",
		"--read-only",
		"--tmpfs", "/tmp",
		"--security-opt=no-new-privileges",
		"--cap-drop=ALL",
		"--memory=" + e.cfg.Sandbox.MemoryLimit,
		"--cpus=" + e.cfg.Sandbox.CPULimit,
		"--network=host",
		e.cfg.Sandbox.Image,
		"-p", prompt,
		"--output-format", "json",
	}
}

func buildPrompt(alert model.Alert) string {
	return fmt.Sprintf(`あなたはセキュリティエンジニアです。以下のDependabotセキュリティアラートについて、開発エンジニア向けに日本語で解説してください。
回答は必ず以下のJSON形式のみで出力してください。JSON以外のテキスト（説明文、前置き、コードブロックなど）は含めないでください。

フィールド:
- impact: この脆弱性によって何が侵害されるか。攻撃者が何をできるようになるか、どんな情報や機能が危険にさらされるかを箇条書きで3〜5項目で具体的に説明する。各項目は「• 」で始め、改行（\n）で区切る
- recommendation: 推奨アクション (approve/reject/manual-review)
- reasoning: このパッケージを「どのように使っていたら」侵害される可能性があるか。具体的なコードパターンや使用方法を箇条書きで3〜5項目で例示する。各項目は「• 」で始め、改行（\n）で区切る

アラート情報:
- パッケージ: %s (%s)
- 重要度: %s
- CVE: %s
- CVSS: %.1f
- 概要: %s
- 修正バージョン: %s
- リポジトリ: %s/%s

{"impact":"...","recommendation":"...","reasoning":"..."}`,
		alert.PackageName, alert.PackageEcosystem,
		alert.Severity,
		alert.CVEID,
		alert.CVSSScore,
		alert.Summary,
		alert.FixedIn,
		alert.Owner, alert.Repo,
	)
}

type claudeJSONOutput struct {
	Result string `json:"result"`
}

// claudeStreamEvent は claude --output-format json の新しいストリーム形式の各イベント
type claudeStreamEvent struct {
	Type    string `json:"type"`
	IsError bool   `json:"is_error"`
	Result  string `json:"result"`
}

func parseEvaluation(data []byte) (*model.Evaluation, error) {
	// 旧形式: {"result": "..."} オブジェクト
	var cOut claudeJSONOutput
	if err := json.Unmarshal(data, &cOut); err == nil && cOut.Result != "" {
		data = []byte(cOut.Result)
	} else {
		// 新形式: [{"type":"system",...},{"type":"result","result":"..."},...] 配列
		var events []claudeStreamEvent
		if err := json.Unmarshal(data, &events); err == nil {
			for _, e := range events {
				if e.Type == "result" {
					if e.IsError || e.Result == "" {
						return nil, fmt.Errorf("claude評価がエラー終了しました")
					}
					data = []byte(e.Result)
					break
				}
			}
		}
	}

	// JSON部分を抽出（前後のテキストを除去）
	extracted, found := extractJSON(data)
	if !found {
		slog.Error("評価結果にJSONが含まれていません", "raw", string(data))
		return nil, fmt.Errorf("評価結果にJSONが含まれていません: %.200s", string(data))
	}

	var eval model.Evaluation
	if err := json.Unmarshal(extracted, &eval); err != nil {
		slog.Error("評価結果パース失敗", "raw", string(data), "extracted", string(extracted), "error", err)
		return nil, fmt.Errorf("評価結果パース失敗: %w", err)
	}
	return &eval, nil
}

func extractJSON(data []byte) ([]byte, bool) {
	// 最初の { から最後の } までを抽出
	start := -1
	end := -1
	for i, b := range data {
		if b == '{' && start == -1 {
			start = i
		}
		if b == '}' {
			end = i
		}
	}
	if start >= 0 && end > start {
		return data[start : end+1], true
	}
	return data, false
}
