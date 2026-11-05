package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
)

var errRSSConflict = errors.New("RSS設定が更新されています")
var errRSSInput = errors.New("RSS設定が不正です")

func (s *Server) updateRSS(w http.ResponseWriter, r *http.Request, mutate func(*config.Config) error) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "フォームパース失敗", http.StatusBadRequest)
		return
	}
	expected, err := strconv.ParseUint(r.FormValue("revision"), 10, 64)
	if err != nil {
		http.Error(w, "revisionが不正です", http.StatusBadRequest)
		return
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if expected != s.cfg.ConfigRevision {
		http.Error(w, errRSSConflict.Error(), http.StatusConflict)
		return
	}
	next, err := config.Clone(*s.cfg)
	if err != nil {
		http.Error(w, "設定の複製に失敗しました", http.StatusInternalServerError)
		return
	}
	if err := mutate(&next); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errRSSConflict) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	if err := next.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	next.ConfigRevision++
	if s.cfgPath != "" {
		if err := config.Save(s.cfgPath, &next); err != nil {
			http.Error(w, "設定保存失敗: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	*s.cfg = next
	s.notifyRiskConfigChanged()
	select {
	case s.feedConfigChanged <- struct{}{}:
	default:
	}
	http.Redirect(w, r, "/settings#rss-feeds", http.StatusSeeOther)
}

func (s *Server) handleRSSAdd(w http.ResponseWriter, r *http.Request) {
	s.updateRSS(w, r, func(cfg *config.Config) error {
		name := strings.TrimSpace(r.FormValue("name"))
		feedURL := strings.TrimSpace(r.FormValue("url"))
		if name == "" || feedURL == "" {
			return fmt.Errorf("%w: 名前とURLを入力してください", errRSSInput)
		}
		for _, existing := range cfg.RSS.Feeds {
			if strings.EqualFold(existing.URL, feedURL) {
				return fmt.Errorf("%w: このURLは登録済みです", errRSSConflict)
			}
		}
		cfg.RSS.Feeds = append(cfg.RSS.Feeds, config.RSSFeed{Name: name, URL: feedURL, Enabled: true})
		cfg.RSS.Enabled = true
		return nil
	})
}

func (s *Server) handleRSSConfig(w http.ResponseWriter, r *http.Request) {
	s.updateRSS(w, r, func(cfg *config.Config) error {
		interval, err := time.ParseDuration(r.FormValue("refresh_interval"))
		if err != nil || interval < 15*time.Minute {
			return fmt.Errorf("%w: 更新間隔は15分以上で指定してください", errRSSInput)
		}
		maxItems, err := strconv.Atoi(r.FormValue("max_items_per_feed"))
		if err != nil || maxItems < 1 || maxItems > 1000 {
			return fmt.Errorf("%w: 1フィードの最大件数は1〜1000で指定してください", errRSSInput)
		}
		retention, err := strconv.Atoi(r.FormValue("retention_days"))
		if err != nil || retention < 1 || retention > 3650 {
			return fmt.Errorf("%w: 保存期間は1〜3650日で指定してください", errRSSInput)
		}
		cfg.RSS.Enabled = r.FormValue("enabled") == "true"
		cfg.RSS.RefreshInterval = interval
		cfg.RSS.MaxItemsPerFeed = maxItems
		cfg.RSS.RetentionDays = retention
		return nil
	})
}

func (s *Server) rssIndex(r *http.Request, cfg *config.Config) (int, error) {
	i, err := strconv.Atoi(r.PathValue("i"))
	if err != nil || i < 0 || i >= len(cfg.RSS.Feeds) {
		return 0, fmt.Errorf("%w: フィードが見つかりません", errRSSInput)
	}
	return i, nil
}

func (s *Server) handleRSSToggle(w http.ResponseWriter, r *http.Request) {
	s.updateRSS(w, r, func(cfg *config.Config) error {
		i, err := s.rssIndex(r, cfg)
		if err != nil {
			return err
		}
		cfg.RSS.Feeds[i].Enabled = !cfg.RSS.Feeds[i].Enabled
		return nil
	})
}

func (s *Server) handleRSSDelete(w http.ResponseWriter, r *http.Request) {
	s.updateRSS(w, r, func(cfg *config.Config) error {
		i, err := s.rssIndex(r, cfg)
		if err != nil {
			return err
		}
		cfg.RSS.Feeds = append(cfg.RSS.Feeds[:i], cfg.RSS.Feeds[i+1:]...)
		if len(cfg.RSS.Feeds) == 0 {
			cfg.RSS.Enabled = false
		}
		return nil
	})
}
