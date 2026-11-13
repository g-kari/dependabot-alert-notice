package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	slackgo "github.com/slack-go/slack"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/evaluator"
	"github.com/g-kari/dependabot-alert-notice/internal/ghcommand"
)

type streamEvent struct {
	Type    string `json:"type"` // "gh" | "claude" | "codex" | "hermes" | "slack" | "sandbox" | "target" | "done"
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Owner   string `json:"owner,omitempty"`
	Repo    string `json:"repo,omitempty"`
	Count   int    `json:"count"`
}

type toolResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type targetResult struct {
	Owner   string `json:"owner"`
	Repo    string `json:"repo"`
	OK      bool   `json:"ok"`
	Count   int    `json:"count"`
	Message string `json:"message"`
}

type connectivityResult struct {
	GH      toolResult     `json:"gh"`
	Claude  toolResult     `json:"claude"`
	Codex   toolResult     `json:"codex"`
	Hermes  toolResult     `json:"hermes"`
	Slack   toolResult     `json:"slack"`
	Sandbox toolResult     `json:"sandbox"`
	Targets []targetResult `json:"targets"`
}

func (s *Server) handleConnectivity(w http.ResponseWriter, r *http.Request) {
	s.render(w, "connectivity.html", nil)
}

func (s *Server) handleConnectivityStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	s.cfgMu.RLock()
	cfg, _ := config.Clone(*s.cfg)
	s.cfgMu.RUnlock()
	gh := newConnectivityGitHub(cfg)

	var sendMu sync.Mutex
	send := func(ev streamEvent) {
		b, _ := json.Marshal(ev)
		sendMu.Lock()
		_, _ = fmt.Fprintf(w, "data: %s\n\n", b)
		flusher.Flush()
		sendMu.Unlock()
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		res := testGH(ctx, gh)
		send(streamEvent{Type: "gh", OK: res.OK, Message: res.Message})
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		res := s.claudeStatus(ctx, cfg)
		send(streamEvent{Type: "claude", OK: res.OK, Message: res.Message})
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		res := s.codexStatus(ctx, cfg)
		send(streamEvent{Type: "codex", OK: res.OK, Message: res.Message})
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		res := testHermesProxy(ctx, cfg)
		send(streamEvent{Type: "hermes", OK: res.OK, Message: res.Message})
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		res := testSlack(ctx, cfg.Slack)
		send(streamEvent{Type: "slack", OK: res.OK, Message: res.Message})
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		res := testEvaluatorSandbox(ctx, cfg)
		send(streamEvent{Type: "sandbox", OK: res.OK, Message: res.Message})
	}()

	for _, t := range cfg.Targets {
		wg.Add(1)
		go func(t config.Target) {
			defer wg.Done()
			var res targetResult
			if t.Repo != "" {
				res = testRepoTarget(ctx, gh, t.Owner, t.Repo)
			} else {
				res = testOrgTarget(ctx, gh, t.Owner)
				if !res.OK {
					res = testUserRepoTarget(ctx, gh, t.Owner)
				}
			}
			send(streamEvent{Type: "target", OK: res.OK, Message: res.Message, Owner: res.Owner, Repo: res.Repo, Count: res.Count})
		}(t)
	}

	wg.Wait()
	send(streamEvent{Type: "done"})
}

func (s *Server) handleConnectivityTest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	s.cfgMu.RLock()
	cfg, _ := config.Clone(*s.cfg)
	s.cfgMu.RUnlock()
	gh := newConnectivityGitHub(cfg)

	var (
		res connectivityResult
		mu  sync.Mutex
		wg  sync.WaitGroup
	)

	wg.Add(6)

	go func() {
		defer wg.Done()
		r := testGH(ctx, gh)
		mu.Lock()
		res.GH = r
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		r := s.claudeStatus(ctx, cfg)
		mu.Lock()
		res.Claude = r
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		r := s.codexStatus(ctx, cfg)
		mu.Lock()
		res.Codex = r
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		r := testHermesProxy(ctx, cfg)
		mu.Lock()
		res.Hermes = r
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		r := testSlack(ctx, cfg.Slack)
		mu.Lock()
		res.Slack = r
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		r := testEvaluatorSandbox(ctx, cfg)
		mu.Lock()
		res.Sandbox = r
		mu.Unlock()
	}()

	wg.Wait()
	res.Targets = testTargets(ctx, gh, cfg.Targets)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// connectivityGitHub shares one immutable authentication context across all probes.
type connectivityGitHub struct {
	runner interface {
		ghcommand.Runner
		Identity(context.Context) (string, error)
		Description() string
	}
	err error
}

func newConnectivityGitHub(cfg config.Config) connectivityGitHub {
	runner, err := ghcommand.New(cfg.GhPath, cfg.GitHubAuth)
	return connectivityGitHub{runner: runner, err: err}
}
func (g connectivityGitHub) Output(ctx context.Context, args ...string) ([]byte, error) {
	if g.err != nil {
		return nil, g.err
	}
	return g.runner.Output(ctx, args...)
}
func testGH(ctx context.Context, gh connectivityGitHub) toolResult {
	if gh.err != nil {
		return toolResult{Message: gh.err.Error()}
	}
	login, err := gh.runner.Identity(ctx)
	if err != nil {
		return toolResult{Message: gh.runner.Description() + ": " + err.Error()}
	}
	return toolResult{OK: true, Message: gh.runner.Description() + ": " + login}
}

func testClaude(ctx context.Context, claudePath string) toolResult {
	out, err := exec.CommandContext(ctx, claudePath, "--version").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return toolResult{OK: false, Message: msg}
	}
	return toolResult{OK: true, Message: strings.TrimSpace(string(out))}
}

func (s *Server) claudeStatus(ctx context.Context, cfg config.Config) toolResult {
	if cfg.Evaluator.Provider != "" && cfg.Evaluator.Provider != "claude" {
		return toolResult{OK: true, Message: "Claude CLIは未選択"}
	}
	return testClaude(ctx, cfg.ClaudePath)
}

func (s *Server) codexStatus(ctx context.Context, cfg config.Config) toolResult {
	if cfg.Evaluator.Provider != "codex" {
		return toolResult{OK: true, Message: "Codex CLIは未選択"}
	}
	return s.codexAuth.Status(ctx, cfg.CodexPath)
}

func testHermesProxy(ctx context.Context, cfg config.Config) toolResult {
	if cfg.Evaluator.Provider != "hermes" {
		return toolResult{OK: true, Message: "Hermes Proxyは未選択"}
	}
	checkable, ok := evaluator.New(&cfg).(interface{ Check(context.Context) error })
	if !ok {
		return toolResult{OK: false, Message: "Hermes Proxyの接続確認を利用できません"}
	}
	if err := checkable.Check(ctx); err != nil {
		return toolResult{OK: false, Message: err.Error()}
	}
	return toolResult{OK: true, Message: "Hermes Proxyのモデル一覧に接続しました (推論なし)"}
}

func testEvaluatorSandbox(ctx context.Context, cfg config.Config) toolResult {
	if cfg.Evaluator.Provider == "hermes" {
		return toolResult{OK: true, Message: "Hermes Proxy APIを使用 (CLI・コンテナ不要)"}
	}
	return testSandbox(ctx, selectedSandbox(cfg))
}

func selectedSandbox(cfg config.Config) config.SandboxConfig {
	sandbox := cfg.Evaluator.Sandbox
	if cfg.Evaluator.Provider == "codex" {
		sandbox.Image = sandbox.CodexImage
		if sandbox.Image == "" {
			sandbox.Image = "dependabot-codex-evaluator:latest"
		}
	}
	return sandbox
}

func testSlack(ctx context.Context, slackCfg config.SlackConfig) toolResult {
	botToken := os.Getenv("SLACK_BOT_TOKEN")
	if botToken == "" {
		botToken = slackCfg.BotToken
	}
	if botToken == "" {
		return toolResult{OK: false, Message: "SLACK_BOT_TOKEN が未設定"}
	}
	api := slackgo.New(botToken)
	resp, err := api.AuthTestContext(ctx)
	if err != nil {
		return toolResult{OK: false, Message: "auth.test 失敗: " + err.Error()}
	}
	return toolResult{OK: true, Message: fmt.Sprintf("接続OK: @%s (%s)", resp.User, resp.Team)}
}

func testTargets(ctx context.Context, gh connectivityGitHub, targets []config.Target) []targetResult {
	results := make([]targetResult, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t config.Target) {
			defer wg.Done()
			if t.Repo != "" {
				results[i] = testRepoTarget(ctx, gh, t.Owner, t.Repo)
				return
			}
			// repo未指定 → org APIを試してダメなら全リポジトリにフォールバック
			r := testOrgTarget(ctx, gh, t.Owner)
			if !r.OK {
				r = testUserRepoTarget(ctx, gh, t.Owner)
			}
			results[i] = r
		}(i, t)
	}
	wg.Wait()
	return results
}

func testRepoTarget(ctx context.Context, gh connectivityGitHub, owner, repo string) targetResult {
	endpoint := fmt.Sprintf("/repos/%s/%s/dependabot/alerts?state=open", owner, repo)
	out, err := gh.Output(ctx, "api", endpoint, "--jq", "length")
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return targetResult{Owner: owner, Repo: repo, OK: false, Message: msg}
	}
	count := 0
	_, _ = fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &count)
	return targetResult{Owner: owner, Repo: repo, OK: true, Count: count, Message: fmt.Sprintf("%d 件のアラートを取得", count)}
}

func testOrgTarget(ctx context.Context, gh connectivityGitHub, owner string) targetResult {
	endpoint := fmt.Sprintf("/orgs/%s/dependabot/alerts?state=open", owner)
	out, err := gh.Output(ctx, "api", endpoint, "--jq", "length")
	if err != nil {
		return targetResult{Owner: owner, OK: false, Message: strings.TrimSpace(string(out))}
	}
	count := 0
	_, _ = fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &count)
	return targetResult{Owner: owner, OK: true, Count: count, Message: fmt.Sprintf("org: %d 件のアラートを取得", count)}
}

func testSandbox(ctx context.Context, sandboxCfg config.SandboxConfig) toolResult {
	if !sandboxCfg.Enabled {
		return toolResult{OK: true, Message: "サンドボックス無効（直接実行モード）"}
	}
	// Docker デーモンの疎通確認
	out, err := exec.CommandContext(ctx, "docker", "info", "--format", "{{.ServerVersion}}").CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return toolResult{OK: false, Message: "Docker 接続失敗: " + msg}
	}
	// イメージの存在確認
	imageOut, err := exec.CommandContext(ctx, "docker", "image", "inspect", sandboxCfg.Image, "--format", "{{.Id}}").CombinedOutput()
	if err != nil {
		return toolResult{OK: false, Message: fmt.Sprintf("イメージ %q が見つかりません（docker build が必要です）", sandboxCfg.Image)}
	}
	imageID := strings.TrimSpace(string(imageOut))
	if len(imageID) > 19 {
		imageID = imageID[:19] + "..."
	}
	return toolResult{OK: true, Message: fmt.Sprintf("Docker OK, イメージ %q 確認済み (%s)", sandboxCfg.Image, imageID)}
}

func testUserRepoTarget(ctx context.Context, gh connectivityGitHub, owner string) targetResult {
	// ユーザーリポジトリ一覧を取得して総アラート数をカウント
	reposOut, err := gh.Output(ctx, "repo", "list", owner,
		"--json", "name", "--jq", ".[].name", "--limit", "1000",
	)
	if err != nil {
		return targetResult{Owner: owner, OK: false, Message: "リポジトリ一覧取得失敗: " + err.Error()}
	}

	var repos []string
	for _, line := range strings.Split(strings.TrimSpace(string(reposOut)), "\n") {
		if line != "" {
			repos = append(repos, line)
		}
	}

	// GitHub secondary rate limit: 最大100並列。余裕を持って10に制限
	const concurrency = 10
	sem := make(chan struct{}, concurrency)

	var (
		totalMu sync.Mutex
		total   int
		failed  int
		wg      sync.WaitGroup
	)
	for _, repo := range repos {
		wg.Add(1)
		go func(repo string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			endpoint := fmt.Sprintf("/repos/%s/%s/dependabot/alerts?state=open", owner, repo)
			out, err := gh.Output(ctx, "api", endpoint, "--jq", "length")
			if err != nil {
				totalMu.Lock()
				failed++
				totalMu.Unlock()
				return
			}
			count := 0
			_, _ = fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &count)
			totalMu.Lock()
			total += count
			totalMu.Unlock()
		}(repo)
	}
	wg.Wait()
	if failed > 0 {
		return targetResult{Owner: owner, Message: "GitHub repository checks incomplete"}
	}
	return targetResult{
		Owner:   owner,
		OK:      true,
		Count:   total,
		Message: fmt.Sprintf("全リポジトリ(%d件)合計: %d 件のアラート", len(repos), total),
	}
}
