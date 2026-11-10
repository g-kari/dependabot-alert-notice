package enrichmentrelease

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

func validateCertificate(c Certificate) error {
	if c.Version != CertificateVersion || !validUUID(c.OperationID) || !validUUID(c.IntentID) ||
		(c.Connector != "epss_feed" && c.Connector != "kev_feed") || c.Generation <= 0 ||
		!validDigest(c.ReservedDigest) || !validDigest(c.TerminalPreviousDigest) || !validDigest(c.TerminalDigest) ||
		len(c.Receipt) > 128 {
		return invalid("certificate binding")
	}
	switch c.Kind {
	case "no_run":
		if c.TerminalSequence != 2 || c.TerminalPreviousDigest != c.ReservedDigest || c.RunID != nil || c.Receipt != "" {
			return invalid("certificate no-run")
		}
	case "success", "failed":
		if c.TerminalSequence != 4 && c.TerminalSequence != 5 || c.RunID == nil || !validUUID(*c.RunID) {
			return invalid("certificate prepared")
		}
		if c.Kind == "success" && !validReceipt(c.Receipt) || c.Kind == "failed" && c.Receipt != "" {
			return invalid("certificate receipt")
		}
	default:
		return invalid("certificate kind")
	}
	return nil
}

func encodeCertificate(c Certificate) ([]byte, error) {
	if err := validateCertificate(c); err != nil {
		return nil, err
	}
	owned := c
	if c.RunID != nil {
		id := *c.RunID
		owned.RunID = &id
	}
	data, err := json.Marshal(owned)
	if err != nil || len(data) > MaxCertificateBytes {
		return nil, invalid("certificate encoding")
	}
	return data, nil
}

func decodeCertificate(data []byte) (Certificate, error) {
	empty := Certificate{}
	if len(data) == 0 || len(data) > MaxCertificateBytes || !utf8.Valid(data) || !validEscapes(data) {
		return empty, invalid("certificate input")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return empty, invalid("certificate object")
	}
	var c Certificate
	var seen uint16
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return empty, invalid("certificate key")
		}
		name, ok := key.(string)
		if !ok {
			return empty, invalid("certificate key")
		}
		index := certificateField(name)
		if index < 0 || seen&(1<<index) != 0 {
			return empty, invalid("certificate unknown or duplicate key")
		}
		seen |= 1 << index
		value, err := d.Token()
		if err != nil {
			return empty, invalid("certificate value")
		}
		switch index {
		case 0, 4, 6:
			number, ok := value.(json.Number)
			if !ok {
				return empty, invalid("certificate integer type")
			}
			n, err := strconv.ParseInt(string(number), 10, 64)
			if err != nil {
				return empty, invalid("certificate integer")
			}
			switch index {
			case 0:
				if n != CertificateVersion {
					return empty, invalid("certificate version")
				}
				c.Version = CertificateVersion
			case 4:
				c.Generation = n
			case 6:
				c.TerminalSequence = n
			}
		case 10:
			if value != nil {
				s, ok := value.(string)
				if !ok || len(s) > 36 {
					return empty, invalid("certificate run type")
				}
				c.RunID = &s
			}
		default:
			s, ok := value.(string)
			if !ok || len(s) > 128 {
				return empty, invalid("certificate string type")
			}
			switch index {
			case 1:
				c.OperationID = s
			case 2:
				c.IntentID = s
			case 3:
				c.Connector = s
			case 5:
				c.ReservedDigest = s
			case 7:
				c.TerminalPreviousDigest = s
			case 8:
				c.TerminalDigest = s
			case 9:
				c.Kind = s
			case 11:
				c.Receipt = s
			}
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') || seen != (1<<12)-1 {
		return empty, invalid("certificate required field")
	}
	if _, err := d.Token(); err != io.EOF {
		return empty, invalid("certificate trailing data")
	}
	if err := validateCertificate(c); err != nil {
		return empty, err
	}
	return c, nil
}

func certificateField(name string) int {
	switch name {
	case "version":
		return 0
	case "operation_id":
		return 1
	case "intent_id":
		return 2
	case "connector":
		return 3
	case "generation":
		return 4
	case "reserved_digest":
		return 5
	case "terminal_sequence":
		return 6
	case "terminal_previous_digest":
		return 7
	case "terminal_digest":
		return 8
	case "kind":
		return 9
	case "run_id":
		return 10
	case "receipt":
		return 11
	}
	return -1
}

func hex4(b []byte) (uint16, bool) {
	if len(b) < 4 {
		return 0, false
	}
	var n uint16
	for _, c := range b[:4] {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n += uint16(c - '0')
		case c >= 'a' && c <= 'f':
			n += uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			n += uint16(c-'A') + 10
		default:
			return 0, false
		}
	}
	return n, true
}

// JSON's ordinary decoder repairs lone surrogates. Reject them before token
// decoding, while permitting actual escaped backslashes and valid pairs.
func validEscapes(data []byte) bool {
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		v, ok := hex4(data[i+1:])
		if !ok {
			return false
		}
		i += 4
		if v >= 0xdc00 && v <= 0xdfff {
			return false
		}
		if v >= 0xd800 && v <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, ok := hex4(data[i+3:])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
