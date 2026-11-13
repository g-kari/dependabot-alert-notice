package evaluator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/config"
	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

const (
	hermesProxyPlaceholder       = "hermes-proxy"
	maxHermesResponseBytes       = 4 << 20
	maxHermesModelsResponseBytes = 1 << 20
)

type hermesMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type hermesChatRequest struct {
	Model    string          `json:"model"`
	Messages []hermesMessage `json:"messages"`
	Stream   bool            `json:"stream"`
}

type hermesChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

// HermesEvaluator calls the local Hermes subscription proxy as a raw
// OpenAI-compatible model endpoint. It never invokes agent tools or a CLI.
type HermesEvaluator struct {
	cfg    config.EvaluatorConfig
	client *http.Client
}

func newHermesEvaluator(cfg config.EvaluatorConfig) *HermesEvaluator {
	timeout := cfg.Sandbox.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &HermesEvaluator{cfg: cfg, client: hermesHTTPClient(timeout)}
}

func hermesHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (e *HermesEvaluator) baseURL() string {
	base := strings.TrimSpace(e.cfg.HermesBaseURL)
	if base == "" {
		base = config.HermesProxyDefaultURL
	}
	return strings.TrimRight(base, "/")
}

func (e *HermesEvaluator) modelName() string {
	modelName := strings.TrimSpace(e.cfg.HermesModel)
	if modelName == "" {
		return config.HermesProxyDefaultModel
	}
	return modelName
}

func (e *HermesEvaluator) httpClient() *http.Client {
	if e.client != nil {
		return e.client
	}
	timeout := e.cfg.Sandbox.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return hermesHTTPClient(timeout)
}

func (e *HermesEvaluator) Evaluate(parent context.Context, alert model.Alert) (*model.Evaluation, error) {
	timeout := e.cfg.Sandbox.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	body, err := json.Marshal(hermesChatRequest{
		Model:    e.modelName(),
		Messages: []hermesMessage{{Role: "user", Content: buildPrompt(alert)}},
		Stream:   false,
	})
	if err != nil {
		return nil, fmt.Errorf("hermes評価リクエストの作成: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, e.baseURL()+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("hermes評価リクエストの作成: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+hermesProxyPlaceholder)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := e.httpClient().Do(request)
	if err != nil {
		return nil, fmt.Errorf("hermes proxyへの接続失敗: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hermes proxyがHTTP %dを返しました", response.StatusCode)
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxHermesResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("hermes評価レスポンスの読み込み: %w", err)
	}
	if len(responseBody) > maxHermesResponseBytes {
		return nil, fmt.Errorf("hermes評価レスポンスが上限を超えました")
	}
	var result hermesChatResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("hermes proxyのレスポンス形式が不正です: %w", err)
	}
	if len(result.Choices) == 0 || strings.TrimSpace(result.Choices[0].Message.Content) == "" {
		return nil, fmt.Errorf("hermes proxyから評価テキストが返りませんでした")
	}
	return parseHermesEvaluation([]byte(result.Choices[0].Message.Content))
}

func parseHermesEvaluation(data []byte) (*model.Evaluation, error) {
	extracted, found := extractJSON(data)
	if !found {
		return nil, fmt.Errorf("hermes評価結果にJSONが含まれていません")
	}
	var result model.Evaluation
	if err := json.Unmarshal(extracted, &result); err != nil {
		return nil, fmt.Errorf("hermes評価結果JSONの解析に失敗しました: %w", err)
	}
	if strings.TrimSpace(result.Impact) == "" {
		return nil, fmt.Errorf("hermes評価結果のimpactが空です")
	}
	result.Recommendation = strings.TrimSpace(result.Recommendation)
	switch result.Recommendation {
	case "approve", "reject", "manual-review":
	default:
		return nil, fmt.Errorf("hermes評価結果のrecommendationが無効です")
	}
	if strings.TrimSpace(result.Reasoning) == "" {
		return nil, fmt.Errorf("hermes評価結果のreasoningが空です")
	}
	if strings.TrimSpace(result.AWSRisk) == "" {
		return nil, fmt.Errorf("hermes評価結果のaws_riskが空です")
	}
	return &result, nil
}

// Check verifies the local proxy using its model-list endpoint without running
// an inference or sending an alert.
func (e *HermesEvaluator) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, e.baseURL()+"/models", nil)
	if err != nil {
		return fmt.Errorf("hermes proxy確認リクエストの作成: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+hermesProxyPlaceholder)
	request.Header.Set("Accept", "application/json")
	response, err := e.httpClient().Do(request)
	if err != nil {
		return fmt.Errorf("hermes proxyへの接続失敗: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("hermes proxyがHTTP %dを返しました", response.StatusCode)
	}
	var result struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	modelListBody, err := io.ReadAll(io.LimitReader(response.Body, maxHermesModelsResponseBytes+1))
	if err != nil {
		return fmt.Errorf("hermes proxyのモデル一覧の読み込みに失敗しました: %w", err)
	}
	if len(modelListBody) > maxHermesModelsResponseBytes {
		return fmt.Errorf("hermes proxyのモデル一覧が上限を超えました")
	}
	decoder := json.NewDecoder(bytes.NewReader(modelListBody))
	if err := decoder.Decode(&result); err != nil {
		return fmt.Errorf("hermes proxyのモデル一覧形式が不正です: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("hermes proxyのモデル一覧に余分なデータがあります")
	}
	if len(result.Data) == 0 {
		return fmt.Errorf("hermes proxyのモデル一覧が空です")
	}
	for _, available := range result.Data {
		if available.ID == e.modelName() {
			return nil
		}
	}
	return fmt.Errorf("hermes proxyのモデル一覧に設定モデルがありません")
}

// Identity identifies the selected Hermes proxy endpoint and model for cache use.
func (e *HermesEvaluator) Identity(alert model.Alert) *model.EvaluationProvenance {
	return identity(alert, "hermes", e.modelName(), "subscription-proxy", e.baseURL())
}
