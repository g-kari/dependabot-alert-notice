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
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg-123"}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	record := makeRecord(model.SeverityHigh, "CVE-2024-0001")
	msgID, err := c.Notify(record)
	if err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}

	if receivedContentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", receivedContentType)
	}

	if msgID != "msg-123" {
		t.Errorf("messageID = %q, want msg-123", msgID)
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
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg-456"}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	record := makeRecord(model.SeverityCritical, "CVE-2024-9999")
	if _, err := c.Notify(record); err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}
}

// TestNotify_EmbedHasFields はEmbedにfieldsが含まれることを確認
func TestNotify_EmbedHasFields(t *testing.T) {
	var received []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg-789"}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	record := makeRecord(model.SeverityHigh, "CVE-2024-0001")
	if _, err := c.Notify(record); err != nil {
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
	if _, err := c.Notify(record); err == nil {
		t.Error("expected error for non-2xx response, got nil")
	}
}

// TestNotify_EmbedFieldsContainImpactAndReasoning はImpactとReasoningフィールドが含まれることを確認
func TestNotify_EmbedFieldsContainImpactAndReasoning(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := New(srv.URL)
	record := makeRecord(model.SeverityHigh, "CVE-2024-0001")
	record.Evaluation.Impact = "• Data exposure\n• Privilege escalation"
	record.Evaluation.Reasoning = "• Using with untrusted input"

	if _, err := c.Notify(record); err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}

	var payload webhookPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	fieldNames := make(map[string]bool)
	for _, f := range payload.Embeds[0].Fields {
		fieldNames[f.Name] = true
	}
	if !fieldNames["侵害される内容"] {
		t.Error("embed should contain '侵害される内容' field")
	}
	if !fieldNames["侵害される使い方"] {
		t.Error("embed should contain '侵害される使い方' field")
	}
}

// TestNotify_EmbedFieldsNoRisk はRiskフィールドが含まれないことを確認
func TestNotify_EmbedFieldsNoRisk(t *testing.T) {
	var received []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg-x"}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	record := makeRecord(model.SeverityHigh, "CVE-2024-0001")

	if _, err := c.Notify(record); err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}

	var payload webhookPayload
	if err := json.Unmarshal(received, &payload); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	for _, f := range payload.Embeds[0].Fields {
		if f.Name == "Risk" {
			t.Error("embed should NOT contain 'Risk' field")
		}
	}
}

// TestNotify_EmptyWebhookURL はWebhookURLが空のときエラーになることを確認
func TestNotify_EmptyWebhookURL(t *testing.T) {
	c := New("")
	record := makeRecord(model.SeverityHigh, "CVE-2024-0001")
	if _, err := c.Notify(record); err == nil {
		t.Error("expected error for empty webhookURL, got nil")
	}
}

// TestNotify_WaitTrue はリクエストURLに?wait=trueが付与されることを確認
func TestNotify_WaitTrue(t *testing.T) {
	var requestURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestURL = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg-wait"}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	record := makeRecord(model.SeverityHigh, "CVE-2024-0001")
	if _, err := c.Notify(record); err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}
	if requestURL != "/?wait=true" {
		t.Errorf("request URL = %q, want /?wait=true", requestURL)
	}
}

// TestNotifyResolved_PatchesMessage は対応済み通知がPATCHリクエストを送ることを確認
func TestNotifyResolved_PatchesMessage(t *testing.T) {
	var patchMethod string
	var patchPath string
	var patchBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		patchMethod = r.Method
		patchPath = r.URL.Path
		patchBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg-resolved"}`))
	}))
	defer srv.Close()

	c := New(srv.URL)
	record := makeRecord(model.SeverityHigh, "CVE-2024-0001")
	record.DiscordMessageID = "discord-msg-42"

	if err := c.NotifyResolved(record); err != nil {
		t.Fatalf("NotifyResolved returned error: %v", err)
	}

	if patchMethod != http.MethodPatch {
		t.Errorf("method = %q, want PATCH", patchMethod)
	}
	if patchPath != "/messages/discord-msg-42" {
		t.Errorf("path = %q, want /messages/discord-msg-42", patchPath)
	}

	var payload webhookPayload
	if err := json.Unmarshal(patchBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if len(payload.Embeds) == 0 {
		t.Fatal("resolved payload should have embeds")
	}
	if payload.Embeds[0].Title == "" {
		t.Error("resolved embed should have a title")
	}
}

// TestNotifyResolved_NoMessageID はDiscordMessageIDが空のときスキップすることを確認
func TestNotifyResolved_NoMessageID(t *testing.T) {
	c := New("https://example.com/webhook")
	record := makeRecord(model.SeverityHigh, "CVE-2024-0001")
	record.DiscordMessageID = ""

	if err := c.NotifyResolved(record); err != nil {
		t.Errorf("NotifyResolved with empty messageID should not error: %v", err)
	}
}
