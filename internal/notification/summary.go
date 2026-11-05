// Package notification はSlack・Discord共通のリポジトリ集約表示を提供する。
package notification

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
	"github.com/g-kari/dependabot-alert-notice/internal/policy"
)

// Summary は表示の省略に影響されない通知対象の未解決件数を保持する。
type Summary struct {
	Owner, Repo                              string
	Total, Done, Pending, Evaluating, Failed int
	Severities                               map[model.Severity]int
	Records                                  []*model.AlertRecord
}

// Build は監視対象・重要度フィルタを適用し、重要度・番号順に並べる。
func Build(records []*model.AlertRecord, cfg config.Config, owner, repo string) Summary {
	s := Summary{Owner: owner, Repo: repo, Severities: map[model.Severity]int{}}
	if !policy.IsMonitored(cfg.Targets, owner, repo) {
		return s
	}
	for _, r := range records {
		if r == nil || r.ResolvedAt != nil || !strings.EqualFold(r.Alert.Owner, owner) || !strings.EqualFold(r.Alert.Repo, repo) || !cfg.ShouldNotify(string(r.Alert.Severity)) {
			continue
		}
		s.Total++
		s.Severities[r.Alert.Severity]++
		s.Records = append(s.Records, r)
		switch r.EvalStatus {
		case model.EvalStatusDone:
			s.Done++
		case model.EvalStatusEvaluating:
			s.Evaluating++
		case model.EvalStatusFailed:
			s.Failed++
		default:
			s.Pending++
		}
	}
	rank := map[model.Severity]int{model.SeverityCritical: 0, model.SeverityHigh: 1, model.SeverityMedium: 2, model.SeverityLow: 3}
	sort.Slice(s.Records, func(i, j int) bool {
		a, b := s.Records[i].Alert, s.Records[j].Alert
		if rank[a.Severity] != rank[b.Severity] {
			return rank[a.Severity] < rank[b.Severity]
		}
		if a.Number != b.Number {
			return a.Number < b.Number
		}
		return a.ID < b.ID
	})
	return s
}

// Text は件数を常に全件分表示し、重要な一覧を最大10件に制限する。
func (s Summary) Text() string {
	text := s.countsText()
	count := 0
	for _, r := range s.Records {
		if count == 10 {
			break
		}
		text += fmt.Sprintf("\n• [%s] #%d %s（AI: %s）", r.Alert.Severity, r.Alert.Number, Limit(SingleLine(r.Alert.PackageName), 90), r.EvalStatus)
		count++
	}
	if count < s.Total {
		text += fmt.Sprintf("\nほか%d件を省略。全件はWeb UIで確認してください。", s.Total-count)
	}
	return text
}

// CompactText は定期通知を件数と詳細画面への案内に絞る。
func (s Summary) CompactText() string {
	return s.countsText() + "\nアラートの詳細・AI評価は Web UI / TUI で確認してください。"
}

func (s Summary) countsText() string {
	return fmt.Sprintf("未解決: %d件（通知対象）\nCritical: %d / High: %d / Medium: %d / Low: %d\nAI評価 完了: %d / 待ち: %d / 評価中: %d / 失敗: %d\n", s.Total, s.Severities[model.SeverityCritical], s.Severities[model.SeverityHigh], s.Severities[model.SeverityMedium], s.Severities[model.SeverityLow], s.Done, s.Pending, s.Evaluating, s.Failed)
}

// SingleLine は通知の見出し・一覧に外部入力の改行や制御文字を持ち込まない。
func SingleLine(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return ' '
		}
		return r
	}, s)
}

// Limit はUTF-16コード単位の上限を守って省略し、絵文字も途中で切らない。
func Limit(value string, max int) string {
	if max <= 0 {
		return ""
	}
	units := 0
	for _, r := range value {
		n := 1
		if r > 0xffff {
			n = 2
		}
		if units+n > max {
			used := 0
			for i, r := range value {
				size := 1
				if r > 0xffff {
					size = 2
				}
				if used+size > max-1 {
					return value[:i] + "…"
				}
				used += size
			}
		}
		units += n
	}
	return value
}
