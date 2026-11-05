package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// EvaluationCacheLifetime bounds reuse even when a model alias or runtime image
// changes outside the application's settings. Manual evaluation bypasses it.
const EvaluationCacheLifetime = 24 * time.Hour

// EvaluationProvenance is application-supplied evidence about an AI result.
// Paths and authentication data are not persisted; RuntimeHash is a digest.
type EvaluationProvenance struct {
	Provider      string    `json:"provider"`
	Model         string    `json:"model"`
	Mode          string    `json:"mode"`
	RuntimeHash   string    `json:"runtime_hash"`
	PromptVersion string    `json:"prompt_version"`
	InputHash     string    `json:"input_hash"`
	CacheKey      string    `json:"cache_key"`
	EvaluatedAt   time.Time `json:"evaluated_at"`
	Reused        bool      `json:"reused,omitempty"`
}

// Key returns a stable identity excluding evaluation time and reuse flags.
// Unresolved CLI defaults and incomplete provenance cannot be cache identities.
func (p EvaluationProvenance) Key() string {
	if p.Provider == "" || p.Model == "" || p.Mode == "" || p.PromptVersion == "" || !evaluationDigest(p.InputHash) || !evaluationDigest(p.RuntimeHash) {
		return ""
	}
	identity := [6]string{p.Provider, p.Model, p.Mode, p.RuntimeHash, p.PromptVersion, p.InputHash}
	body, _ := json.Marshal(identity) // A fixed array of strings cannot fail.
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}

// Reusable checks identity integrity and the original inference age. Copying a
// result never renews its lifetime, and future timestamps fail closed.
func (p EvaluationProvenance) Reusable(now time.Time) bool {
	key := p.Key()
	return key != "" && p.CacheKey == key && !p.EvaluatedAt.IsZero() && !now.Before(p.EvaluatedAt) && now.Sub(p.EvaluatedAt) < EvaluationCacheLifetime
}

func evaluationDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
