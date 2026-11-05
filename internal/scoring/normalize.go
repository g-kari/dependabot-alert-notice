package scoring

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// NormalizeCVSS converts a CVSS base score/vector into bounded impact axes.
// A score without a vector cannot identify individual axes and therefore
// returns a conservative interval rather than pretending they are known.
func NormalizeCVSS(score float64, known bool, version, vector string) model.TechnicalImpact {
	unknown := model.Interval{Low: 0, High: 1}
	result := model.TechnicalImpact{Confidentiality: unknown, Integrity: unknown, Availability: unknown, Privilege: unknown, CVSSVersion: version, CVSSVector: vector}
	if !known || score < 0 || score > 10 {
		return result
	}
	if strings.TrimSpace(vector) == "" {
		return result
	}
	result.Confidentiality = model.Interval{}
	result.Integrity = model.Interval{}
	result.Availability = model.Interval{}
	result.Privilege = model.Interval{}
	seenC, seenI, seenA, seenP := false, false, false, false
	parts := strings.Split(vector, "/")
	for _, part := range parts {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		iv, ok := cvssValue(kv[1])
		if !ok {
			continue
		}
		switch kv[0] {
		case "C", "VC", "SC":
			result.Confidentiality = maxInterval(result.Confidentiality, iv)
			seenC = true
		case "I", "VI", "SI":
			result.Integrity = maxInterval(result.Integrity, iv)
			seenI = true
		case "A", "VA", "SA":
			result.Availability = maxInterval(result.Availability, iv)
			seenA = true
		case "PR", "UI", "AC", "AT":
			result.Privilege = iv
			seenP = true
		}
	}
	if !seenC {
		result.Confidentiality = unknown
	}
	if !seenI {
		result.Integrity = unknown
	}
	if !seenA {
		result.Availability = unknown
	}
	if !seenP {
		result.Privilege = unknown
	}
	result.C, result.I, result.A, result.X = result.Confidentiality, result.Integrity, result.Availability, result.Privilege
	return result
}

func maxInterval(a, b model.Interval) model.Interval {
	if b.Low > a.Low {
		a.Low = b.Low
	}
	if b.High > a.High {
		a.High = b.High
	}
	return a
}

// Normalize is a concise alias used by services that already have a CVSS
// record but do not need to refer to the CVSS-specific name.
func Normalize(score float64, known bool, version, vector string) model.TechnicalImpact {
	return NormalizeCVSS(score, known, version, vector)
}

var cvssMetric = regexp.MustCompile(`^[A-Z]{1,3}$`)

func cvssValue(v string) (model.Interval, bool) {
	if !cvssMetric.MatchString(v) {
		return model.Interval{}, false
	}
	// CVSS impact metrics are deliberately mapped monotonically. Unknown
	// metric symbols remain unknown rather than being treated as safe.
	values := map[string]float64{"N": 0, "L": .5, "H": 1, "P": .75, "U": .5, "R": .75, "C": 1, "I": 1, "A": 1}
	n, ok := values[v]
	if !ok {
		return model.Interval{}, false
	}
	return model.Interval{Low: n, High: n}, true
}

// ParseCVSSScore is useful for records that only carry a numeric value.
func ParseCVSSScore(value string) (float64, bool) {
	n, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	return n, err == nil && n >= 0 && n <= 10
}
