package web

import (
	"fmt"
	"net/url"
	"strconv"
)

// parseConsoleAssetDetailValues gives only this nested UI query an outer budget.
// The caller passes the unchanged API part budget (4096). A generated inner
// query of at most partBudget bytes may expand to 3*partBudget when QueryEscape
// encodes it. Add the literal key, one separator and at most partBudget bytes of
// canonical Finding filters: 13 + 3*4096 + 1 + 4096 = 16398 bytes. Both decoded
// parts still have their original 4096-byte guards and semantic validators.
func parseConsoleAssetDetailValues(raw string, partBudget int) (url.Values, error) {
	const innerKey = "assets_query="
	if partBudget < 1 || partBudget > (int(^uint(0)>>1)-len(innerKey)-1)/4 {
		return nil, fmt.Errorf("invalid asset detail query budget")
	}
	outerBudget := len(innerKey) + 3*partBudget + 1 + partBudget
	values, err := parseBoundedConsoleValues(raw, outerBudget, "q", "source", "severity", "source_status", "cve", "limit", "offset", "assets_query")
	if err != nil {
		return nil, err
	}
	if inner := values.Get("assets_query"); inner != "" {
		if _, err := parseBoundedConsoleValues(inner, partBudget, "q", "provider", "account", "region", "environment", "criticality", "source", "limit", "offset"); err != nil {
			return nil, fmt.Errorf("invalid asset return query: %w", err)
		}
	}
	filters := url.Values{}
	for key, items := range values {
		if key != "assets_query" {
			filters[key] = items
		}
	}
	if len(filters.Encode()) > partBudget {
		return nil, fmt.Errorf("asset finding query is too long")
	}
	return values, nil
}

func parseBoundedConsoleValues(raw string, budget int, allowed ...string) (url.Values, error) {
	if len(raw) > budget {
		return nil, fmt.Errorf("console query is too long")
	}
	values, err := url.ParseQuery(raw)
	if err != nil {
		return nil, fmt.Errorf("parse console query: %w", err)
	}
	for key, items := range values {
		known := false
		for _, name := range allowed {
			if name == key {
				known = true
				break
			}
		}
		if !known || len(items) != 1 {
			return nil, fmt.Errorf("unknown or duplicate console parameter")
		}
	}
	return values, nil
}

// validateConsoleAssetReturnBudget prevents an accepted noncanonical list query
// (for example raw UTF-8) from producing an oversized canonical return query.
// Reserve the largest allowed limit/offset widths, so later page links fit too.
func validateConsoleAssetReturnBudget(values url.Values, budget, maxLimit, maxOffset int) error {
	reserved := url.Values{}
	for key, items := range values {
		reserved[key] = items
	}
	reserved.Set("limit", strconv.Itoa(maxLimit))
	reserved.Set("offset", strconv.Itoa(maxOffset))
	if len(reserved.Encode()) > budget {
		return fmt.Errorf("canonical asset query is too long")
	}
	return nil
}

// consoleAssetDetailURL keeps return-list state and Finding filters separate.
// In particular an empty outer source must never inherit the return-list source.
func consoleAssetDetailURL(id string, returnQuery url.Values, source string) string {
	values := url.Values{"assets_query": {returnQuery.Encode()}}
	if source != "" {
		values.Set("source", source)
	}
	return "/assets/" + url.PathEscape(id) + "?" + values.Encode()
}
