package web

import (
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	records := s.store.List()
	sort.Slice(records, func(i, j int) bool {
		return records[i].Alert.CreatedAt.After(records[j].Alert.CreatedAt)
	})

	s.render(w, "dashboard.html", struct {
		Records []*model.AlertRecord
	}{Records: records})
}

func (s *Server) handleDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "不正なID", http.StatusBadRequest)
		return
	}

	record, err := s.store.Get(id)
	if err != nil {
		http.Error(w, "アラートが見つかりません", http.StatusNotFound)
		return
	}

	s.render(w, "detail.html", record)
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "不正なID", http.StatusBadRequest)
		return
	}

	if err := s.merger.Approve(r.Context(), id); err != nil {
		slog.Error("マージ承認失敗", "alertID", id, "error", err)
		http.Error(w, "マージ失敗: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleReject(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "不正なID", http.StatusBadRequest)
		return
	}

	if err := s.merger.Reject(id); err != nil {
		slog.Error("却下失敗", "alertID", id, "error", err)
		http.Error(w, "却下失敗: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	logs := s.store.ListLogs()

	// 新しい順に表示
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].Timestamp.After(logs[j].Timestamp)
	})

	s.render(w, "logs.html", struct {
		Logs []model.LogEntry
	}{Logs: logs})
}

// --- 設定 ---

type settingsData struct {
	Config      *config.Config
	Flash       string // 保存成功メッセージ
	Error       string
	EnvBotToken bool // SLACK_BOT_TOKEN が環境変数で設定されているか
	EnvAppToken bool // SLACK_APP_TOKEN が環境変数で設定されているか
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()

	s.render(w, "settings.html", settingsData{
		Config:      cfg,
		EnvBotToken: os.Getenv("SLACK_BOT_TOKEN") != "",
		EnvAppToken: os.Getenv("SLACK_APP_TOKEN") != "",
	})
}

func (s *Server) handleSettingsSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "フォームパース失敗", http.StatusBadRequest)
		return
	}

	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()

	// poll_interval
	if v := r.FormValue("poll_interval"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			s.cfg.PollInterval = d
		}
	}

	// log_level
	if v := r.FormValue("log_level"); v != "" {
		s.cfg.LogLevel = v
	}

	// claude_path / gh_path
	if v := r.FormValue("claude_path"); v != "" {
		s.cfg.ClaudePath = v
	}
	if v := r.FormValue("gh_path"); v != "" {
		s.cfg.GhPath = v
	}

	// slack.channel_id（トークンは環境変数のみ）
	s.cfg.Slack.ChannelID = r.FormValue("slack_channel_id")

	// evaluator sandbox
	s.cfg.Evaluator.Sandbox.Enabled = r.FormValue("sandbox_enabled") == "true"
	if v := r.FormValue("sandbox_image"); v != "" {
		s.cfg.Evaluator.Sandbox.Image = v
	}
	if v := r.FormValue("sandbox_memory"); v != "" {
		s.cfg.Evaluator.Sandbox.MemoryLimit = v
	}
	if v := r.FormValue("sandbox_cpu"); v != "" {
		s.cfg.Evaluator.Sandbox.CPULimit = v
	}
	if v := r.FormValue("sandbox_timeout"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			s.cfg.Evaluator.Sandbox.Timeout = d
		}
	}

	// 保存
	if s.cfgPath != "" {
		if err := config.Save(s.cfgPath, s.cfg); err != nil {
			slog.Error("設定保存失敗", "error", err)
			s.render(w, "settings.html", settingsData{
				Config: s.cfg,
				Error:  "設定の保存に失敗しました: " + err.Error(),
			})
			return
		}
	}

	slog.Info("設定を保存しました")
	s.store.AddLog(model.LogEntry{
		Timestamp: time.Now(),
		Level:     "info",
		Message:   "設定を保存しました",
	})

	http.Redirect(w, r, "/settings?saved=1", http.StatusSeeOther)
}

func (s *Server) handleTargetAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "フォームパース失敗", http.StatusBadRequest)
		return
	}

	owner := r.FormValue("owner")
	repo := r.FormValue("repo")
	if owner == "" {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	s.cfgMu.Lock()
	s.cfg.Targets = append(s.cfg.Targets, config.Target{Owner: owner, Repo: repo})
	cfg := s.cfg
	s.cfgMu.Unlock()

	if s.cfgPath != "" {
		if err := config.Save(s.cfgPath, cfg); err != nil {
			slog.Error("設定保存失敗", "error", err)
		}
	}

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleTargetDelete(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("i"))
	if err != nil {
		http.Error(w, "不正なインデックス", http.StatusBadRequest)
		return
	}

	s.cfgMu.Lock()
	if idx >= 0 && idx < len(s.cfg.Targets) {
		s.cfg.Targets = append(s.cfg.Targets[:idx], s.cfg.Targets[idx+1:]...)
	}
	cfg := s.cfg
	s.cfgMu.Unlock()

	if s.cfgPath != "" {
		if err := config.Save(s.cfgPath, cfg); err != nil {
			slog.Error("設定保存失敗", "error", err)
		}
	}

	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}
