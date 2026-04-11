package discord

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

func makeRecord(severity model.Severity, cveID string) *model.AlertRecord {
	return &model.AlertRecord{
		Alert: model.Alert{
			ID:          1,
			PackageName: "lodash",
			Owner:       "testorg",
			Repo:        "repo1",
			Severity:    severity,
			CVEID:       cveID,
			CVSSScore:   7.5,
			Summary:     "Prototype pollution",
			FixedIn:     "4.17.21",
			HTMLURL:     "https://github.com/testorg/repo1/security/dependabot/1",
			CreatedAt:   time.Now(),
		},
		Evaluation: &model.Evaluation{
			Risk:           "high",
			Recommendation: "approve",
			Reasoning:      "テスト用の評価理由",
		},
		State: model.AlertStatePending,
	}
}

// TestNotify_PostsToWebhook はWebhook URLにPOSTリクエストが送信されることを確認
func TestNotify_PostsToWebhook(t *testing.T) {
	var received []byte
	var receivedContentType string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedContentType = r.Header.Get("Content-Type")
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL)
	record := makeRecord(model.SeverityHigh, "CVE-2024-0001")
	if err := c.Notify(record); err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}

	if receivedContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", receivedContentType)
	}

	var payload webhookPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if len(payload.Embeds) == 0 {
		t.Fatal("embeds should not be empty")
	}
}

// TestNotify_EmbedContent はEmbedのtitleとcolorが正しいことを確認
func TestNotify_EmbedContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL)
	record := makeRecord(model.SeverityCritical, "CVE-2024-9999")
	if err := c.Notify(record); err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}
}

// TestNotify_EmbedHasFields はEmbedにfieldsが含まれることを確認
func TestNotify_EmbedHasFields(t *testing.T) {
	var received []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL)
	record := makeRecord(model.SeverityHigh, "CVE-2024-0001")
	if err := c.Notify(record); err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}

	var payload webhookPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	embed := payload.Embeds[0]
	if len(embed.Fields) == 0 {
		t.Error("embed.Fields should not be empty")
	}
}

// TestNotify_HTTPErrorReturnsError はWebhookが2xx以外を返したときエラーになることを確認
func TestNotify_HTTPErrorReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	c := New(srv.URL)
	record := makeRecord(model.SeverityHigh, "CVE-2024-0001")
	if err := c.Notify(record); err == nil {
		t.Error("expected error for non-2xx response, got nil")
	}
}

// TestNotify_EmptyWebhookURL はWebhookURLが空のときエラーになることを確認
func TestNotify_EmptyWebhookURL(t *testing.T) {
	c := New("")
	record := makeRecord(model.SeverityHigh, "CVE-2024-0001")
	if err := c.Notify(record); err == nil {
		t.Error("expected error for empty webhookURL, got nil")
	}
}
