package enrichmentjournal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"time"
	"unicode/utf8"
)

var errInvalidCheckpoint = errors.New("invalid operation checkpoint")
var timeType = reflect.TypeOf(time.Time{})

func invalid(reason string) error {
	return fmt.Errorf("journal %s: %w", reason, errInvalidCheckpoint)
}

func encodeCheckpoint(checkpoint Checkpoint) ([]byte, error) {
	if err := validateCheckpoint(checkpoint); err != nil {
		return nil, err
	}
	// UTC changes representation only, preserving every instant. It does not
	// fill missing clocks. Never mutate the caller's slices or date pointers.
	canonical := canonicalCheckpoint(checkpoint)
	data, err := json.Marshal(canonical)
	if err != nil {
		return nil, invalid("encoding")
	}
	if len(data) > MaxCheckpointBytes {
		return nil, invalid("encoded size")
	}
	return data, nil
}

func decodeCheckpoint(data []byte) (Checkpoint, error) {
	if len(data) == 0 || len(data) > MaxCheckpointBytes || !utf8.Valid(data) || !validEscapes(data) {
		return Checkpoint{}, invalid("input")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := checkValue(d, reflect.TypeOf(Checkpoint{}), 0); err != nil {
		return Checkpoint{}, err
	}
	if _, err := d.Token(); err != io.EOF {
		return Checkpoint{}, invalid("trailing data")
	}
	var checkpoint Checkpoint
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		return Checkpoint{}, invalid("decoding")
	}
	if err := validateCheckpoint(checkpoint); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

func checkValue(d *json.Decoder, typ reflect.Type, depth int) error {
	if depth > 16 {
		return invalid("depth")
	}
	token, err := d.Token()
	if err != nil {
		return invalid("JSON")
	}
	if typ.Kind() == reflect.Pointer {
		if token == nil {
			return nil
		}
		typ = typ.Elem()
	}
	if typ == timeType {
		s, ok := token.(string)
		if !ok || len(s) > 64 {
			return invalid("clock type")
		}
		if _, err := time.Parse(time.RFC3339Nano, s); err != nil {
			return invalid("clock encoding")
		}
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return invalid("object type")
		}
		fields := make(map[string]reflect.Type, typ.NumField())
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			fields[f.Tag.Get("json")] = f.Type
		}
		seen := make(map[string]bool, len(fields))
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return invalid("object key")
			}
			name, ok := key.(string)
			fieldType, known := fields[name]
			if !ok || !known || seen[name] {
				return invalid("unknown or duplicate key")
			}
			seen[name] = true
			if err := checkValue(d, fieldType, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') || len(seen) != len(fields) {
			return invalid("required field")
		}
	case reflect.Slice:
		// Entries may be nil in a legal empty partial feed. Required field
		// presence is still checked; target/selection nil is rejected by shape.
		if token == nil {
			return nil
		}
		if token != json.Delim('[') {
			return invalid("array type")
		}
		count := 0
		for d.More() {
			if count >= 200 {
				return invalid("array bound")
			}
			count++
			if err := checkValue(d, typ.Elem(), depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return invalid("array end")
		}
	case reflect.String:
		s, ok := token.(string)
		if !ok || len(s) > 128 {
			return invalid("string type or bound")
		}
	case reflect.Bool:
		if _, ok := token.(bool); !ok {
			return invalid("boolean type")
		}
	case reflect.Int:
		n, ok := token.(json.Number)
		if !ok {
			return invalid("integer type")
		}
		if _, err := strconv.ParseInt(string(n), 10, 64); err != nil {
			return invalid("integer encoding")
		}
	case reflect.Float64:
		n, ok := token.(json.Number)
		if !ok {
			return invalid("number type")
		}
		if _, err := strconv.ParseFloat(string(n), 64); err != nil {
			return invalid("number encoding")
		}
	default:
		return invalid("unsupported type")
	}
	return nil
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

func canonicalCheckpoint(c Checkpoint) Checkpoint {
	if c.Prepared == nil {
		return c
	}
	p := *c.Prepared
	p.Attempt.Targets = append([]Target(nil), p.Attempt.Targets...)
	p.Attempt.StartedAt = p.Attempt.StartedAt.UTC()
	if p.Failure != nil {
		f := *p.Failure
		f.FinishedAt = f.FinishedAt.UTC()
		p.Failure = &f
	}
	if p.Completion != nil {
		completion := *p.Completion
		completion.FinishedAt = completion.FinishedAt.UTC()
		completion.Feed.PublishedAt = completion.Feed.PublishedAt.UTC()
		completion.Feed.ObservedAt = completion.Feed.ObservedAt.UTC()
		completion.Feed.SelectedCVEs = append([]string(nil), completion.Feed.SelectedCVEs...)
		if completion.Feed.Entries != nil {
			completion.Feed.Entries = append([]Entry{}, completion.Feed.Entries...)
		}
		for i := range completion.Feed.Entries {
			e := &completion.Feed.Entries[i]
			if e.EPSS != nil {
				n := *e.EPSS
				e.EPSS = &n
			}
			if e.Percentile != nil {
				n := *e.Percentile
				e.Percentile = &n
			}
			if e.KEVDateAdded != nil {
				at := e.KEVDateAdded.UTC()
				e.KEVDateAdded = &at
			}
		}
		p.Completion = &completion
	}
	c.Prepared = &p
	return c
}
