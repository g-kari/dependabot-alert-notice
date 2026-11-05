package store

import (
	"context"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestListRepositoriesUsesPersistedRepositoryColumns(t *testing.T) {
	s := New()
	t.Cleanup(func() { _ = s.Close() })
	for i, repo := range []string{"API", "api", "web"} {
		s.Save(&model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: repo, Number: i + 1}, NotifiedAt: time.Now()})
	}
	// Summary data is authoritative in indexed columns; report payloads are not needed.
	if _, err := s.db.Exec(`UPDATE alert_records SET alert_json='{}'`); err != nil {
		t.Fatal(err)
	}
	repos := s.ListRepositories()
	if len(repos) != 2 || repos[0].Owner != "org" || repos[0].AlertCount != 2 || repos[1].Repo != "web" {
		t.Fatalf("repository summaries = %+v", repos)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.QueryRepositories(ctx); err == nil {
		t.Fatal("canceled summary query should report an error")
	}
}
