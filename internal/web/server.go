package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentrefresh"
	"github.com/g-kari/dependabot-alert-notice/internal/feed"
	"github.com/g-kari/dependabot-alert-notice/internal/merger"
	"github.com/g-kari/dependabot-alert-notice/internal/policy"
	"github.com/g-kari/dependabot-alert-notice/internal/queue"
	"github.com/g-kari/dependabot-alert-notice/internal/risk"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	"github.com/yuin/goldmark/v2/parser"
	"github.com/yuin/goldmark/v2/renderer/html"
)

//go:embed templates/*.html static/*
var templateFS embed.FS

type Server struct {
	manualRefreshMu          sync.RWMutex
	manualRefreshController  *enrichmentrefresh.ManualController
	port                     int
	address                  string
	store                    *store.Store
	merger                   merger.Interface
	server                   *http.Server
	cfg                      *config.Config
	cfgPath                  string
	cfgMu                    sync.RWMutex
	pollFn                   func()
	isPolling                bool
	pollingMu                sync.Mutex
	jobQueue                 *queue.Queue
	feedMu                   sync.Mutex
	feedRefreshing           bool
	fetchFeed                func(context.Context, string, feed.FetchOptions) (feed.FetchResult, error)
	feedConfigChanged        chan struct{}
	riskConfigChanged        chan struct{}
	riskWorker               *risk.Worker
	repositoryPolicy         *policy.Guard
	appCtx                   context.Context
	codexAuth                codexAuthClient
	onEvaluatorConfigChanged func(config.Config)
}

func New(cfg *config.Config, cfgPath string, s *store.Store, m merger.Interface) *Server {
	srv := &Server{
		port:              cfg.Web.Port,
		address:           cfg.Web.ListenAddress(),
		store:             s,
		merger:            m,
		cfg:               cfg,
		cfgPath:           cfgPath,
		feedConfigChanged: make(chan struct{}, 1),
		riskConfigChanged: make(chan struct{}, 1),
		fetchFeed:         feed.FetchWithCache,
		codexAuth:         &cliCodexAuth{},
	}
	srv.riskWorker = risk.NewWorker(s, riskSettingsSource{server: srv})
	srv.repositoryPolicy = policy.NewGuard(riskSettingsSource{server: srv}.Snapshot)
	if guarded, ok := m.(interface{ SetRepositoryPolicy(*policy.Guard) }); ok {
		guarded.SetRepositoryPolicy(srv.repositoryPolicy)
	}
	return srv
}

// SetPollFn はWebUIから手動ポーリングを実行するための関数をセットする
func (s *Server) SetPollFn(fn func()) {
	s.pollFn = fn
}

// SetQueue はJobQueueをサーバーにセットする
func (s *Server) SetQueue(q *queue.Queue) {
	s.jobQueue = q
}

// SetEvaluatorConfigChanged は設定保存後に評価先を切り替えるコールバックを登録する。
func (s *Server) SetEvaluatorConfigChanged(fn func(config.Config)) {
	s.onEvaluatorConfigChanged = fn
}

// templateFuncs はテンプレートで使用するカスタム関数
var templateFuncs = template.FuncMap{
	"mul100": func(v float64) float64 { return v * 100 },
	"sub":    func(a, b int) int { return a - b },
	// joinStrings はスライスをセパレータで結合する
	"joinStrings":       strings.Join,
	"riskPriorityLabel": riskPriorityLabel,
	"riskStatusLabel":   riskStatusLabel,
	// topContributor はコントリビューター一覧の先頭を返す（空なら空文字列）
	"topContributor": func(cs []string) string {
		if len(cs) == 0 {
			return ""
		}
		return cs[0]
	},
	// contributorsSummary は最大5件を表示し、超えた場合は「他N名」を付ける
	"contributorsSummary": func(cs []string) string {
		if len(cs) == 0 {
			return ""
		}
		if len(cs) <= 5 {
			return strings.Join(cs, ", ")
		}
		return strings.Join(cs[:5], ", ") + fmt.Sprintf(" (他%d名)", len(cs)-5)
	},
	"markdown": func(s string) template.HTML {
		if s == "" {
			return ""
		}
		var buf bytes.Buffer
		source := []byte(s)
		// Keep parser and renderer state local to each request and retain the
		// default safe renderer: raw HTML and dangerous URLs are not enabled.
		doc := parser.New().Parse(source)
		if err := html.New().Render(&buf, source, doc); err != nil {
			return template.HTML(template.HTMLEscapeString(s))
		}
		return template.HTML(buf.String())
	},
}

// render はlayout.html + 指定ページテンプレートをペアでパースして実行する。
// 全ページを一度にParseすると{{define "content"}}が上書きされるため、ページごとに個別にパースする。
func (s *Server) render(w http.ResponseWriter, page string, data any) {
	tmpl, err := template.New("").Funcs(templateFuncs).ParseFS(templateFS, "templates/layout.html", "templates/"+page)
	if err != nil {
		slog.Error("テンプレートパース失敗", "page", page, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("テンプレートレンダリング失敗", "page", page, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// Handler exposes the complete HTTP handler for integration tests and for
// embedders that provide their own listener/middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.registerTUI(mux)
	s.registerFindingsAPI(mux)
	s.registerFindingsConsole(mux)
	mux.HandleFunc("GET /", s.handleDashboard)
	mux.HandleFunc("GET /alerts/{id}", s.handleDetail)
	mux.HandleFunc("POST /alerts/{id}/approve", s.handleApprove)
	mux.HandleFunc("POST /alerts/{id}/reject", s.handleReject)
	mux.HandleFunc("GET /logs", s.handleLogs)
	mux.HandleFunc("GET /reports/vulnerabilities", s.handleVulnerabilityReport)
	mux.HandleFunc("POST /reports/vulnerabilities/refresh", s.handleVulnerabilityRefresh)
	mux.HandleFunc("GET /api/logs-stream", s.handleLogsStream)
	mux.HandleFunc("GET /settings", s.handleSettings)
	mux.HandleFunc("GET /settings/repositories", s.handleSettings)
	mux.HandleFunc("POST /settings", s.handleSettingsSave)
	mux.HandleFunc("POST /settings/targets/add", s.handleTargetAdd)
	mux.HandleFunc("POST /settings/targets/{i}/delete", s.handleTargetDelete)
	mux.HandleFunc("POST /settings/targets/{i}/excludes/add", s.handleExcludeAdd)
	mux.HandleFunc("POST /settings/targets/{i}/excludes/{j}/delete", s.handleExcludeDelete)
	mux.HandleFunc("POST /settings/repositories/exclude", s.handleRepositoryExclude)
	mux.HandleFunc("POST /settings/repositories/include", s.handleRepositoryInclude)
	mux.HandleFunc("POST /settings/rss/add", s.handleRSSAdd)
	mux.HandleFunc("POST /settings/rss/config", s.handleRSSConfig)
	mux.HandleFunc("POST /settings/rss/{i}/toggle", s.handleRSSToggle)
	mux.HandleFunc("POST /settings/rss/{i}/delete", s.handleRSSDelete)
	mux.HandleFunc("GET /settings/codex/status", s.handleCodexAuthStatus)
	mux.HandleFunc("POST /settings/codex/login", s.handleCodexLogin)
	mux.HandleFunc("GET /settings/connectivity", s.handleConnectivity)
	mux.HandleFunc("POST /api/connectivity-test", s.handleConnectivityTest)
	mux.HandleFunc("GET /api/connectivity-stream", s.handleConnectivityStream)
	mux.HandleFunc("POST /api/poll", s.handlePoll)
	mux.HandleFunc("POST /api/poll/repo", s.handlePollRepo)
	mux.HandleFunc("POST /api/poll/target/{i}", s.handlePollTarget)
	mux.HandleFunc("POST /api/evaluate/{id}", s.handleEnqueueEvaluate)
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		data, err := templateFS.ReadFile("static/favicon.ico")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/x-icon")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		_, _ = w.Write(data)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("HTTP", "method", r.Method, "path", r.URL.Path)
		if r.URL.Path == "/findings" || strings.HasPrefix(r.URL.Path, "/findings/") {
			if !s.nativeFindingsGET(w, r) {
				return
			}
		}
		if r.Method == http.MethodPost && (r.URL.Path == "/reports/vulnerabilities/refresh" || r.URL.Path == "/settings/repositories/exclude" || r.URL.Path == "/settings/repositories/include" || r.URL.Path == "/settings/codex/login" || strings.HasPrefix(r.URL.Path, "/settings/rss/")) {
			if !validCSRF(w, r) {
				return
			}
		}
		if s.serveManualEnrichmentAPI(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func issueCSRF(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie("csrf_token"); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	token := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	return token
}

func validCSRF(w http.ResponseWriter, r *http.Request) bool {
	cookie, err := r.Cookie("csrf_token")
	if err != nil || cookie.Value == "" {
		http.Error(w, "CSRF tokenが必要です", http.StatusForbidden)
		return false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "フォームパース失敗", http.StatusBadRequest)
		return false
	}
	token := r.FormValue("csrf_token")
	if token == "" || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(token)) != 1 {
		http.Error(w, "CSRF tokenが不正です", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) Start(ctx context.Context) error {
	s.appCtx = ctx

	s.server = &http.Server{
		Addr:    s.address,
		Handler: s.Handler(),
	}

	slog.Info("WebUIサーバー開始", "port", s.port)

	return serveHTTP(ctx, s.server, s.server.ListenAndServe)
}
