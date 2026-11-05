package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func TestAWSEvaluationPersistsAndLegacyRowsStayReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "aws.db")
	s, err := NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	r := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 1}, Evaluation: &model.Evaluation{AWSRisk: "IAMロールを利用する場合の条件"}, NotifiedAt: time.Now()}
	s.Save(r)
	legacy := &model.AlertRecord{Alert: model.Alert{Owner: "org", Repo: "repo", Number: 2}, Evaluation: &model.Evaluation{Impact: "従来の評価"}, NotifiedAt: time.Now()}
	s.Save(legacy)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = NewWithPath(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	got, err := s.Get(r.Alert.ID)
	if err != nil || got.Evaluation.AWSRisk != r.Evaluation.AWSRisk {
		t.Fatalf("saved=%+v %v", got, err)
	}
	old, err := s.Get(legacy.Alert.ID)
	if err != nil || old.Evaluation.AWSRisk != "" || old.Evaluation.Impact != "従来の評価" {
		t.Fatalf("legacy=%+v %v", old, err)
	}
}
