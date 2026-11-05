// Package control defines the local terminal control protocol.
package control

import "github.com/g-kari/dependabot-alert-notice/internal/model"

// Settings is a redacted YAML configuration and optimistic revision.
type Settings struct {
	Revision uint64 `json:"revision"`
	YAML     string `json:"yaml"`
	CSRF     string `json:"csrf_token,omitempty"`
}

// Saved reports whether an application restart is needed for saved settings.
type Saved struct {
	Revision        uint64 `json:"revision"`
	RestartRequired bool   `json:"restart_required"`
}

// Status contains the bounded terminal dashboard and credential availability.
type Status struct {
	Alerts   []*model.AlertRecord `json:"alerts"`
	Logs     []model.LogEntry     `json:"logs"`
	Polling  bool                 `json:"polling"`
	SlackBot bool                 `json:"slack_bot"`
	SlackApp bool                 `json:"slack_app"`
	Discord  bool                 `json:"discord"`
}

// CredentialState exposes availability without returning a credential value.
type CredentialState struct {
	Active      bool `json:"active"`
	Saved       bool `json:"saved"`
	Managed     bool `json:"managed"`
	Environment bool `json:"environment"`
}

// CredentialsStatus distinguishes saved credentials from the running connections.
type CredentialsStatus struct {
	Revision        uint64          `json:"revision"`
	RestartRequired bool            `json:"restart_required"`
	SlackBot        CredentialState `json:"slack_bot"`
	SlackApp        CredentialState `json:"slack_app"`
	Discord         CredentialState `json:"discord"`
}

// CredentialChanges applies explicit overrides; null returns to environment/YAML.
type CredentialChanges struct {
	Revision uint64             `json:"revision"`
	Values   map[string]*string `json:"values"`
}
