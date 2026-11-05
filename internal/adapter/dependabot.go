// Package adapter translates source-specific records into the common security
// model without performing external actions or changing legacy workflows.
package adapter

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// DependabotFinding is a normalized source observation and its related entities.
// The original AlertRecord remains the authority for Dependabot-specific work.
type DependabotFinding struct {
	Asset       model.Asset
	Finding     model.Finding
	Observation model.Observation
}

// NormalizeDependabot maps a legacy record without mutating it. Source identity
// is account/repository/alert number, never CVE or local database ID. runID and
// observedAt must identify the actual ingestion, including legacy backfills.
func NormalizeDependabot(record model.AlertRecord, runID string, observedAt time.Time) (DependabotFinding, error) {
	owner := strings.ToLower(strings.TrimSpace(record.Alert.Owner))
	repo := strings.ToLower(strings.TrimSpace(record.Alert.Repo))
	if !validIdentityPart(owner) || !validIdentityPart(repo) || record.Alert.Number <= 0 {
		return DependabotFinding{}, fmt.Errorf("normalize dependabot: owner, repository and positive alert number are required")
	}
	if strings.TrimSpace(runID) == "" || observedAt.IsZero() {
		return DependabotFinding{}, fmt.Errorf("normalize dependabot: ingest run ID and observation time are required")
	}

	nativeAssetID := owner + "/" + repo
	nativeFindingID := nativeAssetID + ":" + strconv.Itoa(record.Alert.Number)
	assetID := stableSecurityID("asset", "github", "repository", owner, nativeAssetID)
	findingID := stableSecurityID("finding", "dependabot", owner, nativeFindingID)
	sourceStatus := dependabotSourceStatus(record)
	canonicalKey, err := dependabotCanonicalKey(record.Alert)
	if err != nil {
		return DependabotFinding{}, fmt.Errorf("normalize dependabot correlation key: %w", err)
	}

	// Marshal the complete source alert in stable struct field order, excluding
	// the local DB key. Approval, evaluation and notification fields deliberately
	// stay out of source evidence. ResolvedAt is represented by source status.
	alert := record.Alert
	alert.ID = 0
	evidence, err := json.Marshal(struct {
		Alert        model.Alert        `json:"alert"`
		SourceStatus model.SourceStatus `json:"source_status"`
	}{alert, sourceStatus})
	if err != nil {
		return DependabotFinding{}, fmt.Errorf("normalize dependabot source evidence: %w", err)
	}
	digest := sha256.Sum256(evidence)
	fingerprint := hex.EncodeToString(digest[:])
	observedAt = observedAt.UTC()
	firstSeen := record.Alert.CreatedAt.UTC()
	if firstSeen.IsZero() {
		firstSeen = observedAt
	}

	vulnerabilityID := strings.ToUpper(strings.TrimSpace(record.Alert.CVEID))
	if vulnerabilityID == "" {
		vulnerabilityID = strings.ToUpper(strings.TrimSpace(record.Alert.GHSAID))
	}

	return DependabotFinding{
		Asset: model.Asset{
			ID: assetID, Type: "repository", Provider: "github", Account: owner, NativeID: nativeAssetID,
		},
		Finding: model.Finding{
			ID: findingID, Category: "vulnerability", AssetID: assetID,
			CanonicalKey: canonicalKey, Severity: record.Alert.Severity,
			TriageStatus: model.TriageStatusNew, SourceStatus: sourceStatus,
			FirstSeen: firstSeen, LastSeen: observedAt,
			Title: record.Alert.Summary, VulnerabilityID: vulnerabilityID,
			PackageName: record.Alert.PackageName, PackageEcosystem: record.Alert.PackageEcosystem, FixedVersion: record.Alert.FixedIn,
		},
		Observation: model.Observation{
			ID:     stableSecurityID("observation", findingID, runID, fingerprint),
			Source: "dependabot", Account: owner, SourceFindingID: nativeFindingID,
			FindingID: findingID, IngestRunID: runID, RawRef: record.Alert.HTMLURL,
			ObservedAt: observedAt, Fingerprint: fingerprint,
		},
	}, nil
}

func validIdentityPart(value string) bool {
	return value != "" && !strings.ContainsAny(value, "/:") && !strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	})
}

func dependabotSourceStatus(record model.AlertRecord) model.SourceStatus {
	if record.ResolvedAt != nil {
		return model.SourceStatusResolved
	}
	switch strings.ToLower(strings.TrimSpace(record.Alert.State)) {
	case "", "open":
		// Records created before native state was persisted represented open alerts.
		return model.SourceStatusActive
	case "fixed":
		return model.SourceStatusResolved
	case "dismissed", "auto_dismissed":
		return model.SourceStatusSuppressed
	default:
		return model.SourceStatusUnknown
	}
}

func dependabotCanonicalKey(alert model.Alert) (string, error) {
	advisory := strings.ToUpper(strings.TrimSpace(alert.CVEID))
	if advisory == "" {
		advisory = strings.ToUpper(strings.TrimSpace(alert.GHSAID))
	}
	if advisory == "" {
		return "", nil
	}
	// JSON tuples avoid delimiter collisions and preserve all string characters.
	encoded, err := json.Marshal([4]string{advisory, strings.ToLower(strings.TrimSpace(alert.PackageEcosystem)), alert.PackageName, alert.ManifestPath})
	if err != nil {
		return "", fmt.Errorf("encode correlation tuple: %w", err)
	}
	return string(encoded), nil
}

func stableSecurityID(parts ...string) string {
	// Length prefixes make the identity unambiguous even if a source value
	// contains separators. UUID version 8 denotes this SHA-256-based layout.
	var identity []byte
	for _, part := range parts {
		identity = binary.BigEndian.AppendUint64(identity, uint64(len(part)))
		identity = append(identity, part...)
	}
	digest := sha256.Sum256(identity)
	digest[6] = (digest[6] & 0x0f) | 0x80
	digest[8] = (digest[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", digest[:4], digest[4:6], digest[6:8], digest[8:10], digest[10:16])
}
