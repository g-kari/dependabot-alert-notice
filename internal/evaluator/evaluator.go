package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

type Evaluator interface {
	Evaluate(ctx context.Context, alert model.Alert) (*model.Evaluation, error)
}

func New(cfg *config.Config) Evaluator {
	return newEvaluator(cfg, runtime.GOOS, runtime.GOARCH)
}

func newEvaluator(cfg *config.Config, osName, arch string) Evaluator {
	if cfg.Evaluator.Provider == "hermes" {
		return newHermesEvaluator(cfg.Evaluator)
	}
	backend := cfg.Evaluator.Sandbox.Runtime
	if backend == "apple" || (backend == "auto" && osName == "darwin" && arch == "arm64") {
		return &AppleEvaluator{cfg: cfg.Evaluator}
	}
	if cfg.Evaluator.Provider == "codex" {
		return &CodexEvaluator{cfg: cfg.Evaluator, path: cfg.CodexPath}
	}
	if cfg.Evaluator.Sandbox.Enabled || backend == "podman" {
		return &DockerEvaluator{cfg: cfg.Evaluator}
	}
	return &DirectEvaluator{claudePath: cfg.ClaudePath, model: cfg.Evaluator.ClaudeModel}
}

// DirectEvaluator はclaude CLIを直接実行する（テスト用・sandbox無効時）
type DirectEvaluator struct {
	claudePath string
	model      string
}

func (e *DirectEvaluator) Evaluate(ctx context.Context, alert model.Alert) (*model.Evaluation, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	prompt := buildPrompt(alert)
	cmd := exec.CommandContext(ctx, e.claudePath, claudeArgs(prompt, e.model)...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("claude -p 実行失敗: %w", err)
	}

	return parseEvaluation(out)
}

// DockerEvaluator はDockerコンテナ内でclaude CLIを実行する（セキュリティ隔離）
type DockerEvaluator struct {
	cfg config.EvaluatorConfig
	run func(context.Context, codexCommand) ([]byte, error)
}

func (e *DockerEvaluator) Evaluate(ctx context.Context, alert model.Alert) (*model.Evaluation, error) {
	if !e.cfg.Sandbox.Enabled {
		return nil, fmt.Errorf("コンテナ隔離が無効です。隔離なしでは評価しません")
	}
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
		claudeHome = filepath.Join(home, ".claude")
	}

	prompt := buildPrompt(alert)

	args := e.buildDockerArgs(prompt, claudeHome)
	runner := e.run
	if runner == nil {
		runner = runCodexCommand
	}
	out, err := runner(ctx, codexCommand{Name: containerRuntime(e.cfg.Sandbox.Runtime), Args: args})
	if err != nil {
		return nil, fmt.Errorf("%s run claude -p 実行失敗: %w", containerRuntime(e.cfg.Sandbox.Runtime), err)
	}

	return parseEvaluation(out)
}

// buildDockerArgs はDockerコンテナ実行用のコマンド引数を生成する（テスト可能にするため分離）
func (e *DockerEvaluator) buildDockerArgs(prompt, claudeHome string) []string {
	// claudeHome は ~/.claude ディレクトリのパス。その親がホームディレクトリ
	homeDir := filepath.Dir(claudeHome)
	claudeJSON := filepath.Join(homeDir, ".claude.json")
	args := []string{
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
	}
	if e.cfg.Sandbox.Runtime == "podman" {
		args = append(args, "--userns=keep-id:uid=1000,gid=1000", "--user=1000:1000")
	}
	args = append(args, e.cfg.Sandbox.Image)
	return append(args, claudeArgs(prompt, e.cfg.ClaudeModel)...)
}

func containerRuntime(selected string) string {
	if selected == "podman" {
		return "podman"
	}
	return "docker"
}

func claudeArgs(prompt, model string) []string {
	args := []string{"-p", prompt, "--output-format", "json"}
	if model != "" {
		args = append(args, "--model", model)
	}
	return args
}

func buildPrompt(alert model.Alert) string {
	return fmt.Sprintf(`あなたはセキュリティエンジニアです。以下のDependabotセキュリティアラートについて、開発エンジニア向けに日本語で解説してください。
回答は必ず以下のJSON形式のみで出力してください。JSON以外のテキスト（説明文、前置き、コードブロックなど）は含めないでください。

フィールド:
- impact: この脆弱性によって何が侵害されるか。攻撃者が何をできるようになるか、どんな情報や機能が危険にさらされるかを箇条書きで3〜5項目で具体的に説明する。各項目は「• 」で始め、改行（\n）で区切る
- recommendation: 推奨アクション (approve/reject/manual-review)
- reasoning: このパッケージを「どのように使っていたら」侵害される可能性があるか。具体的なコードパターンや使用方法を箇条書きで3〜5項目で例示する。各項目は「• 」で始め、改行（\n）で区切る
- aws_risk: AWSで危険になる利用条件を独立して説明する。実際のAWS構成は取得していません。「こう使っていたら危険」という条件付き評価とし、実構成・侵害・権限を断定しない。脆弱性と関係する条件に絞り、各条件について想定される影響、確認すべき設定、具体的な対策を箇条書きで示す。不明点は確認項目にする。必要に応じてEC2/ECS/EKS/Lambdaでの実行、ALB/API Gatewayの公開経路、IAMロール権限、メタデータ/認証情報へのアクセス、S3/RDSへの到達性、CI/ビルド環境のAWS権限を検討するが、全サービスを機械的に列挙しない。関連が判断できなければその旨と確認事項を示す。AWSへの接続や認証情報取得は行わない。

アラート情報:
- パッケージ: %s (%s)
- 重要度: %s
- CVE: %s
- GHSA: %s
- CVSS: %g (確認済み: %t。未確認の値を安全と判断しない)
- 概要: %s
- 修正バージョン: %s
- 脆弱性対象バージョン: %s
- マニフェスト: %s
- 依存スコープ: %s
- リポジトリ: %s/%s

{"impact":"...","recommendation":"...","reasoning":"...","aws_risk":"..."}`,
		alert.PackageName, alert.PackageEcosystem,
		alert.Severity,
		alert.CVEID, alert.GHSAID,
		alert.CVSSScore, alert.CVSSKnown,
		alert.Summary,
		alert.FixedIn,
		alert.VulnerableVersionRange, alert.ManifestPath, alert.DependencyScope,
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
