package web

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sync"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/merger"
	"github.com/g-kari/dependabot-alert-notice/internal/queue"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
	"github.com/yuin/goldmark"
)

//go:embed templates/*.html
var templateFS embed.FS

type Server struct {
	port      int
	store     *store.Store
	merger    merger.Interface
	server    *http.Server
	cfg       *config.Config
	cfgPath   string
	cfgMu     sync.RWMutex
	pollFn    func()
	isPolling bool
	pollingMu sync.Mutex
	jobQueue  *queue.Queue
}

func New(cfg *config.Config, cfgPath string, s *store.Store, m merger.Interface) *Server {
	return &Server{
		port:    cfg.Web.Port,
		store:   s,
		merger:  m,
		cfg:     cfg,
		cfgPath: cfgPath,
	}
}

// SetPollFn はWebUIから手動ポーリングを実行するための関数をセットする
func (s *Server) SetPollFn(fn func()) {
	s.pollFn = fn
}

// SetQueue はJobQueueをサーバーにセットする
func (s *Server) SetQueue(q *queue.Queue) {
	s.jobQueue = q
}

// templateFuncs はテンプレートで使用するカスタム関数
var templateFuncs = template.FuncMap{
	"mul100": func(v float64) float64 { return v * 100 },
	"markdown": func(s string) template.HTML {
		if s == "" {
			return ""
		}
		var buf bytes.Buffer
		if err := goldmark.Convert([]byte(s), &buf); err != nil {
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

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", s.handleDashboard)
	mux.HandleFunc("GET /alerts/{id}", s.handleDetail)
	mux.HandleFunc("POST /alerts/{id}/approve", s.handleApprove)
	mux.HandleFunc("POST /alerts/{id}/reject", s.handleReject)
	mux.HandleFunc("GET /logs", s.handleLogs)
	mux.HandleFunc("GET /api/logs-stream", s.handleLogsStream)
	mux.HandleFunc("GET /settings", s.handleSettings)
	mux.HandleFunc("POST /settings", s.handleSettingsSave)
	mux.HandleFunc("POST /settings/targets/add", s.handleTargetAdd)
	mux.HandleFunc("POST /settings/targets/{i}/delete", s.handleTargetDelete)
	mux.HandleFunc("POST /settings/targets/{i}/excludes/add", s.handleExcludeAdd)
	mux.HandleFunc("POST /settings/targets/{i}/excludes/{j}/delete", s.handleExcludeDelete)
	mux.HandleFunc("GET /settings/connectivity", s.handleConnectivity)
	mux.HandleFunc("POST /api/connectivity-test", s.handleConnectivityTest)
	mux.HandleFunc("GET /api/connectivity-stream", s.handleConnectivityStream)
	mux.HandleFunc("POST /api/poll", s.handlePoll)
	mux.HandleFunc("POST /api/poll/target/{i}", s.handlePollTarget)
	mux.HandleFunc("POST /api/evaluate/{id}", s.handleEnqueueEvaluate)

	s.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.port),
		Handler: mux,
	}

	slog.Info("WebUIサーバー開始", "port", s.port)

	go func() {
		<-ctx.Done()
		_ = s.server.Shutdown(context.Background())
	}()

	if err := s.server.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("WebUIサーバーエラー: %w", err)
	}
	return nil
}
