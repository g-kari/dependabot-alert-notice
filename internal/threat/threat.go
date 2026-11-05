// Package threat はKEV/EPSSなど外部脅威情報を正規化する。
package threat

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

// ParseKEV はCISA KEV JSONの必要項目を抽出する。
func ParseKEV(data []byte, fetchedAt time.Time) (map[string]model.ThreatSnapshot, error) {
	var doc struct {
		Vulnerabilities []struct {
			CVEID     string `json:"cveID"`
			DateAdded string `json:"dateAdded"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("KEV JSON解析失敗: %w", err)
	}
	out := make(map[string]model.ThreatSnapshot, len(doc.Vulnerabilities))
	for _, item := range doc.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(item.CVEID))
		if id == "" {
			continue
		}
		snap := model.ThreatSnapshot{AdvisoryKey: "cve:" + id, KEV: true, KEVKnown: true, FetchedAt: fetchedAt.UTC()}
		if t, err := time.Parse("2006-01-02", item.DateAdded); err == nil {
			u := t.UTC()
			snap.KEVDate = &u
		}
		out[id] = snap
	}
	return out, nil
}

// ParseEPSS はEPSS CSVのヘッダ付きデータを抽出する。
func ParseEPSS(r io.Reader, fetchedAt time.Time) (map[string]model.ThreatSnapshot, error) {
	buffered := bufio.NewReader(r)
	var sourceDate *time.Time
	for {
		prefix, err := buffered.Peek(1)
		if err != nil || prefix[0] != '#' {
			break
		}
		line, err := buffered.ReadSlice('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("EPSSメタデータ読込失敗: %w", err)
		}
		for _, field := range strings.Split(strings.TrimPrefix(string(line), "#"), ",") {
			key, value, ok := strings.Cut(strings.TrimSpace(field), ":")
			if ok && key == "score_date" {
				date, err := time.Parse("2006-01-02", strings.TrimSpace(value))
				if err != nil {
					return nil, fmt.Errorf("EPSS算出日解析失敗: %w", err)
				}
				sourceDate = &date
			}
		}
	}
	reader := csv.NewReader(buffered)
	reader.Comment = '#'
	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("EPSSヘッダー読込失敗: %w", err)
	}
	indexes := map[string]int{}
	for i, h := range header {
		indexes[strings.ToLower(strings.TrimSpace(h))] = i
	}
	cveIdx, ok := indexes["cve"]
	if !ok {
		return nil, fmt.Errorf("EPSS CSVにCVE列がありません")
	}
	epssIdx, ok := indexes["epss"]
	if !ok {
		return nil, fmt.Errorf("EPSS CSVにepss列がありません")
	}
	pctIdx, hasPercentile := indexes["percentile"]
	dateIdx, hasDate := indexes["date"]
	out := map[string]model.ThreatSnapshot{}
	for {
		row, e := reader.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, fmt.Errorf("EPSS CSV読込失敗: %w", e)
		}
		if len(row) <= cveIdx || len(row) <= epssIdx {
			continue
		}
		id := strings.ToUpper(strings.TrimSpace(row[cveIdx]))
		if id == "" {
			continue
		}
		v, e := strconv.ParseFloat(strings.TrimSpace(row[epssIdx]), 64)
		if e != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 {
			return nil, fmt.Errorf("EPSS確率が不正です (%s): %q", id, row[epssIdx])
		}
		snap := model.ThreatSnapshot{AdvisoryKey: "cve:" + id, EPSS: &v, FetchedAt: fetchedAt.UTC(), EPSSDate: sourceDate}
		if hasDate {
			date, err := time.Parse("2006-01-02", strings.TrimSpace(row[dateIdx]))
			if err != nil {
				return nil, fmt.Errorf("EPSS算出日解析失敗 (%s): %w", id, err)
			}
			snap.EPSSDate = &date
		}
		if hasPercentile {
			p, e := strconv.ParseFloat(strings.TrimSpace(row[pctIdx]), 64)
			if e != nil || math.IsNaN(p) || math.IsInf(p, 0) || p < 0 || p > 1 {
				return nil, fmt.Errorf("EPSS百分位が不正です (%s): %q", id, row[pctIdx])
			}
			snap.EPSSPercentile = &p
		}
		out[id] = snap
	}
	return out, nil
}
