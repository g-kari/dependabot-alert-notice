package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
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

	args := []string{
		"run", "--rm",
		"-v", claudeHome + ":/home/node/.claude:ro",
		"--read-only",
		"--tmpfs", "/tmp",
		"--no-new-privileges",
		"--cap-drop=ALL",
		"--memory=" + e.cfg.Sandbox.MemoryLimit,
		"--cpus=" + e.cfg.Sandbox.CPULimit,
		"--network=host",
		e.cfg.Sandbox.Image,
		"-p", prompt,
		"--output-format", "json",
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker run claude -p 実行失敗: %w", err)
	}

	return parseEvaluation(out)
}

func buildPrompt(alert model.Alert) string {
	return fmt.Sprintf(`以下のDependabotセキュリティアラートを評価してください。
回答は必ず以下のJSON形式のみで出力してください。JSON以外のテキスト（説明文、前置き、コードブロックなど）は含めないでください。
フィールド: risk (critical/high/medium/low), impact (影響の説明), recommendation (approve/reject/manual-review), reasoning (判断理由)

アラート情報:
- パッケージ: %s (%s)
- 重要度: %s
- CVE: %s
- CVSS: %.1f
- 概要: %s
- 修正バージョン: %s
- リポジトリ: %s/%s

{"risk":"...","impact":"...","recommendation":"...","reasoning":"..."}`,
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

func parseEvaluation(data []byte) (*model.Evaluation, error) {
	// claude --output-format json の出力は {"result": "..."} 形式
	var cOut claudeJSONOutput
	if err := json.Unmarshal(data, &cOut); err == nil && cOut.Result != "" {
		data = []byte(cOut.Result)
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
