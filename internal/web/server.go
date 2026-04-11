package web

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"sync"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/merger"
	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

type Server struct {
	port    int
	store   *store.Store
	merger  merger.Interface
	server  *http.Server
	cfg     *config.Config
	cfgPath string
	cfgMu   sync.RWMutex
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

// render はlayout.html + 指定ページテンプレートをペアでパースして実行する。
// 全ページを一度にParseすると{{define "content"}}が上書きされるため、ページごとに個別にパースする。
func (s *Server) render(w http.ResponseWriter, page string, data any) {
	tmpl, err := template.ParseFS(templateFS, "templates/layout.html", "templates/"+page)
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
	mux.HandleFunc("GET /settings", s.handleSettings)
	mux.HandleFunc("POST /settings", s.handleSettingsSave)
	mux.HandleFunc("POST /settings/targets/add", s.handleTargetAdd)
	mux.HandleFunc("POST /settings/targets/{i}/delete", s.handleTargetDelete)

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
