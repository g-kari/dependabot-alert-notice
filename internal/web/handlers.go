package web

import (
	"log/slog"
	"net/http"
	"sort"
	"strconv"

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
