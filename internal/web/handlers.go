package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/queue"
)

// dashboardPageSize はダッシュボード1ページあたりの表示グループ数
const dashboardPageSize = 25

// PaginationInfo はページネーション情報を保持する
type PaginationInfo struct {
	Page       int
	TotalPages int
	TotalItems int
	PageSize   int
}

// HasPrev は前のページが存在するか返す
func (p PaginationInfo) HasPrev() bool { return p.Page > 1 }

// HasNext は次のページが存在するか返す
func (p PaginationInfo) HasNext() bool { return p.Page < p.TotalPages }

// Prev は前ページ番号を返す
func (p PaginationInfo) Prev() int { return p.Page - 1 }

// Next は次ページ番号を返す
func (p PaginationInfo) Next() int { return p.Page + 1 }

// paginateCVE はCVEグループスライスをページ単位に切り出す
func paginateCVE(groups []CVEGroup, page int) ([]CVEGroup, PaginationInfo) {
	total := len(groups)
	totalPages := (total + dashboardPageSize - 1) / dashboardPageSize
	if totalPages < 1 {
		totalPages = 1
	}
	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * dashboardPageSize
	end := start + dashboardPageSize
	if end > total {
		end = total
	}
	return groups[start:end], PaginationInfo{Page: page, TotalPages: totalPages, TotalItems: total, PageSize: dashboardPageSize}
}

// paginateRepo はRepoグループスライスをページ単位に切り出す
func paginateRepo(groups []RepoGroup, page int) ([]RepoGroup, PaginationInfo) {
	total := len(groups)
	totalPages := (total + dashboardPageSize - 1) / dashboardPageSize
	if totalPages < 1 {
		totalPages = 1
	}
	if page < 1 {
		page = 1
	}
	if page > totalPages {
		page = totalPages
	}
	start := (page - 1) * dashboardPageSize
	end := start + dashboardPageSize
	if end > total {
		end = total
	}
	return groups[start:end], PaginationInfo{Page: page, TotalPages: totalPages, TotalItems: total, PageSize: dashboardPageSize}
}

// CVEGroup はCVE ID（またはGHSA ID）単位でアラートをまとめたグループ
type CVEGroup struct {
	CVEID       string
	GHSAID      string
	Summary     string
	Severity    model.Severity
	PackageName string
	CVSSScore   float64
	Records     []*model.AlertRecord
}

// RepoGroup はリポジトリ単位でアラートをまとめたグループ
type RepoGroup struct {
	Owner       string
	Repo        string
	MaxSeverity model.Severity
	MaxCVSS     float64
	Records     []*model.AlertRecord
}

// groupByRepo はAlertRecordのリストをリポジトリ単位でグルーピングする。
// グループはMaxSeverity降順 → MaxCVSS降順でソートされる。
// グループ内のRecordsはCreatedAt降順でソートされる。
func groupByRepo(records []*model.AlertRecord) []RepoGroup {
	if len(records) == 0 {
		return []RepoGroup{}
	}

	type groupKey = string
	groupMap := make(map[groupKey]*RepoGroup)
	var keys []string

	for _, r := range records {
		key := r.Alert.Owner + "/" + r.Alert.Repo
		if g, ok := groupMap[key]; ok {
			g.Records = append(g.Records, r)
			if severityOrder[r.Alert.Severity] > severityOrder[g.MaxSeverity] {
				g.MaxSeverity = r.Alert.Severity
				g.MaxCVSS = r.Alert.CVSSScore
			} else if r.Alert.Severity == g.MaxSeverity && r.Alert.CVSSScore > g.MaxCVSS {
				g.MaxCVSS = r.Alert.CVSSScore
			}
		} else {
			groupMap[key] = &RepoGroup{
				Owner:       r.Alert.Owner,
				Repo:        r.Alert.Repo,
				MaxSeverity: r.Alert.Severity,
				MaxCVSS:     r.Alert.CVSSScore,
				Records:     []*model.AlertRecord{r},
			}
			keys = append(keys, key)
		}
	}

	groups := make([]RepoGroup, 0, len(keys))
	for _, k := range keys {
		g := groupMap[k]
		sort.Slice(g.Records, func(i, j int) bool {
			return g.Records[i].Alert.CreatedAt.After(g.Records[j].Alert.CreatedAt)
		})
		groups = append(groups, *g)
	}

	sort.Slice(groups, func(i, j int) bool {
		si, sj := severityOrder[groups[i].MaxSeverity], severityOrder[groups[j].MaxSeverity]
		if si != sj {
			return si > sj
		}
		return groups[i].MaxCVSS > groups[j].MaxCVSS
	})

	return groups
}

// severityOrder はSeverity降順ソート用の優先度マップ
var severityOrder = map[model.Severity]int{
	model.SeverityCritical: 4,
	model.SeverityHigh:     3,
	model.SeverityMedium:   2,
	model.SeverityLow:      1,
}

// groupByCVE はAlertRecordのリストをCVE ID単位でグルーピングする。
// CVE IDが空のアラートはアラートIDをキーに個別グループとして扱う。
// グループはSeverity降順 → CVSS降順でソートされる。
// グループ内のRecordsはCreatedAt降順でソートされる。
func groupByCVE(records []*model.AlertRecord) []CVEGroup {
	if len(records) == 0 {
		return []CVEGroup{}
	}

	groupMap := make(map[string]*CVEGroup)
	// 挿入順を保持するためキーを追跡
	var keys []string

	for _, r := range records {
		key := r.Alert.CVEID
		if key == "" {
			if r.Alert.GHSAID != "" {
				key = "ghsa:" + r.Alert.GHSAID
			} else {
				key = fmt.Sprintf("__noAdvisory_%d", r.Alert.ID)
			}
		}

		if g, ok := groupMap[key]; ok {
			g.Records = append(g.Records, r)
			// グループ内で最も深刻なSeverity/CVSSを保持
			if severityOrder[r.Alert.Severity] > severityOrder[g.Severity] {
				g.Severity = r.Alert.Severity
				g.CVSSScore = r.Alert.CVSSScore
				g.PackageName = r.Alert.PackageName
				g.Summary = r.Alert.Summary
			} else if r.Alert.Severity == g.Severity && r.Alert.CVSSScore > g.CVSSScore {
				g.CVSSScore = r.Alert.CVSSScore
			}
		} else {
			groupMap[key] = &CVEGroup{
				CVEID:       r.Alert.CVEID,
				GHSAID:      r.Alert.GHSAID,
				Summary:     r.Alert.Summary,
				Severity:    r.Alert.Severity,
				PackageName: r.Alert.PackageName,
				CVSSScore:   r.Alert.CVSSScore,
				Records:     []*model.AlertRecord{r},
			}
			keys = append(keys, key)
		}
	}

	groups := make([]CVEGroup, 0, len(keys))
	for _, k := range keys {
		g := groupMap[k]
		// グループ内のRecordsをCreatedAt降順でソート
		sort.Slice(g.Records, func(i, j int) bool {
			return g.Records[i].Alert.CreatedAt.After(g.Records[j].Alert.CreatedAt)
		})
		groups = append(groups, *g)
	}

	// グループをSeverity降順 → CVSS降順でソート
	sort.Slice(groups, func(i, j int) bool {
		si, sj := severityOrder[groups[i].Severity], severityOrder[groups[j].Severity]
		if si != sj {
			return si > sj
		}
		return groups[i].CVSSScore > groups[j].CVSSScore
	})

	return groups
}

// filterByConfig はconfigの除外リストに基づいてAlertRecordをフィルタリングする。
// excludeに設定されたリポジトリのアラートのみ除外し、それ以外は全て表示する。
func filterByConfig(records []*model.AlertRecord, cfg *config.Config) []*model.AlertRecord {
	// owner → targets のマップを構築
	targetsByOwner := make(map[string][]config.Target)
	for _, t := range cfg.Targets {
		targetsByOwner[t.Owner] = append(targetsByOwner[t.Owner], t)
	}

	var filtered []*model.AlertRecord
	for _, r := range records {
		targets, ok := targetsByOwner[r.Alert.Owner]
		if !ok {
			// ターゲット設定にないownerはそのまま表示
			filtered = append(filtered, r)
			continue
		}
		excluded := false
		for _, t := range targets {
			if t.IsExcluded(r.Alert.Repo) {
				excluded = true
				break
			}
		}
		if !excluded {
			filtered = append(filtered, r)
		}
	}
	return filtered
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()

	s.pollingMu.Lock()
	polling := s.isPolling
	s.pollingMu.Unlock()

	records := filterByConfig(s.store.List(), cfg)

	hasEvaluating := false
	for _, rec := range records {
		if rec.EvalStatus == model.EvalStatusEvaluating {
			hasEvaluating = true
			break
		}
	}

	viewMode := r.URL.Query().Get("view")
	if viewMode != "repo" {
		viewMode = "cve"
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	allCVE := groupByCVE(records)
	allRepo := groupByRepo(records)
	pagedCVE, cvePagination := paginateCVE(allCVE, page)
	pagedRepo, repoPagination := paginateRepo(allRepo, page)

	pagination := cvePagination
	if viewMode == "repo" {
		pagination = repoPagination
	}

	s.render(w, "dashboard.html", struct {
		CVEGroups     []CVEGroup
		RepoGroups    []RepoGroup
		ViewMode      string
		IsPolling     bool
		HasEvaluating bool
		Pagination    PaginationInfo
	}{
		CVEGroups:     pagedCVE,
		RepoGroups:    pagedRepo,
		ViewMode:      viewMode,
		IsPolling:     polling,
		HasEvaluating: hasEvaluating,
		Pagination:    pagination,
	})
}

// handlePoll はWebUIから手動でDependabotアラートのポーリングをトリガーする
func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	if s.pollFn == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	s.pollingMu.Lock()
	if s.isPolling {
		s.pollingMu.Unlock()
		http.Error(w, "ポーリング実行中です", http.StatusConflict)
		return
	}
	s.isPolling = true
	s.pollingMu.Unlock()

	go func() {
		defer func() {
			s.pollingMu.Lock()
			s.isPolling = false
			s.pollingMu.Unlock()
		}()
		s.pollFn()
	}()

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handlePollRepo はowner/repoを指定してFetchJobをエンキューする（ダッシュボードリポジトリ別表示から使用）
func (s *Server) handlePollRepo(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "フォームパース失敗", http.StatusBadRequest)
		return
	}
	owner := r.FormValue("owner")
	repo := r.FormValue("repo")
	if owner == "" || repo == "" {
		http.Error(w, "owner/repoが必要です", http.StatusBadRequest)
		return
	}
	if s.jobQueue != nil {
		s.jobQueue.Enqueue(queue.Job{
			Type:    queue.JobFetchAlerts,
			Payload: config.Target{Owner: owner, Repo: repo},
		})
	}
	http.Redirect(w, r, "/?view=repo", http.StatusSeeOther)
}

// handlePollTarget はWebUIから特定ターゲット1件のFetchJobをエンキューする
func (s *Server) handlePollTarget(w http.ResponseWriter, r *http.Request) {
	i, err := strconv.Atoi(r.PathValue("i"))
	if err != nil {
		http.Error(w, "不正なインデックス", http.StatusBadRequest)
		return
	}
	s.cfgMu.RLock()
	targets := s.cfg.Targets
	s.cfgMu.RUnlock()
	if i < 0 || i >= len(targets) {
		http.Error(w, "インデックスが範囲外です", http.StatusBadRequest)
		return
	}
	if s.jobQueue != nil {
		s.jobQueue.Enqueue(queue.Job{
			Type:    queue.JobFetchAlerts,
			Payload: targets[i],
		})
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// handleEnqueueEvaluate は指定アラートのAI評価をJobQueueに積む
func (s *Server) handleEnqueueEvaluate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "不正なID", http.StatusBadRequest)
		return
	}

	if s.jobQueue == nil {
		http.Error(w, "JobQueueが設定されていません", http.StatusServiceUnavailable)
		return
	}

	// 評価ジョブをキューに積む
	s.jobQueue.Enqueue(queue.Job{
		Type:    queue.JobEvaluateAlert,
		Payload: id,
	})

	if ref := r.Referer(); ref != "" {
		http.Redirect(w, r, ref, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
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
	Config            *config.Config
	Flash             string // 保存成功メッセージ
	Error             string
	EnvBotToken       bool   // SLACK_BOT_TOKEN が環境変数で設定されているか
	EnvAppToken       bool   // SLACK_APP_TOKEN が環境変数で設定されているか
	EnvDiscordWebhook bool   // DISCORD_WEBHOOK_URL が環境変数で設定されているか
	AllowedUserIDsStr string // Config.Slack.AllowedUserIDs のカンマ区切り文字列（テンプレート表示用）
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()

	s.render(w, "settings.html", settingsData{
		Config:            cfg,
		EnvBotToken:       os.Getenv("SLACK_BOT_TOKEN") != "",
		EnvAppToken:       os.Getenv("SLACK_APP_TOKEN") != "",
		EnvDiscordWebhook: os.Getenv("DISCORD_WEBHOOK_URL") != "",
		AllowedUserIDsStr: strings.Join(cfg.Slack.AllowedUserIDs, ","),
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

	// slack（トークンは環境変数未設定時のみYAML保存）
	s.cfg.Slack.ChannelID = r.FormValue("slack_channel_id")

	// slack承認許可ユーザー（カンマ区切り → スライス）
	if v := r.FormValue("slack_allowed_user_ids"); v != "" {
		parts := strings.Split(v, ",")
		var ids []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				ids = append(ids, p)
			}
		}
		s.cfg.Slack.AllowedUserIDs = ids
	} else {
		s.cfg.Slack.AllowedUserIDs = nil // 空=全員許可
	}
	if os.Getenv("SLACK_BOT_TOKEN") == "" {
		if v := r.FormValue("slack_bot_token"); v != "" {
			s.cfg.Slack.BotToken = v
		}
	}
	if os.Getenv("SLACK_APP_TOKEN") == "" {
		if v := r.FormValue("slack_app_token"); v != "" {
			s.cfg.Slack.AppToken = v
		}
	}

	// discord.webhook_url（環境変数未設定時のみYAML保存）
	if os.Getenv("DISCORD_WEBHOOK_URL") == "" {
		s.cfg.Discord.WebhookURL = r.FormValue("discord_webhook_url")
	}

	// 取得最低重要度（空=全件取得）
	if v := r.FormValue("fetch_min_severity"); v == "critical" || v == "high" || v == "medium" || v == "low" || v == "" {
		s.cfg.FetchMinSeverity = v
	}

	// 通知最低重要度
	if v := r.FormValue("notify_min_severity"); v == "critical" || v == "high" || v == "medium" || v == "low" {
		s.cfg.NotifyMinSeverity = v
	}

	// 直近活動フィルタ（Nか月以内にpushがあったリポのみ対象）
	if v := r.FormValue("active_months"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			s.cfg.ActiveMonths = n
		}
	}

	// AI自動評価ON/OFF
	s.cfg.Evaluator.AutoEval = r.FormValue("auto_eval") == "true"

	// AI評価最低重要度
	if v := r.FormValue("eval_min_severity"); v == "critical" || v == "high" || v == "medium" || v == "low" {
		s.cfg.Evaluator.MinSeverity = v
	}

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

func (s *Server) handleExcludeAdd(w http.ResponseWriter, r *http.Request) {
	idx, err := strconv.Atoi(r.PathValue("i"))
	if err != nil {
		http.Error(w, "不正なインデックス", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "フォームパース失敗", http.StatusBadRequest)
		return
	}
	repo := r.FormValue("repo")
	if repo == "" {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}

	s.cfgMu.Lock()
	if idx >= 0 && idx < len(s.cfg.Targets) {
		t := &s.cfg.Targets[idx]
		// 重複チェック
		exists := false
		for _, ex := range t.Excludes {
			if ex == repo {
				exists = true
				break
			}
		}
		if !exists {
			t.Excludes = append(t.Excludes, repo)
		}
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

func (s *Server) handleExcludeDelete(w http.ResponseWriter, r *http.Request) {
	i, err := strconv.Atoi(r.PathValue("i"))
	if err != nil {
		http.Error(w, "不正なインデックス", http.StatusBadRequest)
		return
	}
	j, err := strconv.Atoi(r.PathValue("j"))
	if err != nil {
		http.Error(w, "不正なインデックス", http.StatusBadRequest)
		return
	}

	s.cfgMu.Lock()
	if i >= 0 && i < len(s.cfg.Targets) {
		t := &s.cfg.Targets[i]
		if j >= 0 && j < len(t.Excludes) {
			t.Excludes = append(t.Excludes[:j], t.Excludes[j+1:]...)
		}
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
