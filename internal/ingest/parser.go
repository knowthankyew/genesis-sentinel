package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

const (
	// DefaultMaxLineLength matches Genesis's 64 KB line bound.
	DefaultMaxLineLength = 65536
)

var (
	// ErrEmptyInput is returned for blank log lines.
	ErrEmptyInput = errors.New("empty log line")
	// ErrOversizedLine is returned when an untrusted structured line exceeds safe bounds
	// and cannot be decoded without risking metadata/service corruption.
	ErrOversizedLine = errors.New("oversized log line")
)

var syslogSeverityMap = []string{
	"FATAL", // 0: Emergency
	"FATAL", // 1: Alert
	"FATAL", // 2: Critical
	"ERROR", // 3: Error
	"WARN",  // 4: Warning
	"INFO",  // 5: Notice
	"INFO",  // 6: Informational
	"DEBUG", // 7: Debug
}

// ParseRawLog decodes a raw Genesis log line (JSON Lines, Syslog RFC 5424/3164,
// Pipe format, or plain text) into a structured model.LogEvent, matching
// Genesis's internal/parser/multiformat.go semantics while preserving structured
// JSON metadata (such as service=sentinel) even on oversized messages.
func ParseRawLog(id uint64, raw []byte, maxLineLen int, defaultService string) (model.LogEvent, error) {
	if maxLineLen <= 0 {
		maxLineLen = DefaultMaxLineLength
	}
	raw = bytes.TrimRight(raw, "\r\n")
	if len(raw) == 0 {
		return model.LogEvent{}, ErrEmptyInput
	}
	if len(raw) > MaxFrameBytes {
		return model.LogEvent{}, fmt.Errorf("%w: %d bytes exceeds hard frame bound %d", ErrOversizedLine, len(raw), MaxFrameBytes)
	}
	if defaultService == "" {
		defaultService = "genesis"
	}

	// 1. JSON Lines: inspect a JSON-whitespace-trimmed view BEFORE applying maxLineLen
	// truncation so trailing spaces or large messages never drop the closing '}' and
	// relabel a structured record (e.g. service=sentinel) as plain text.
	trimmedJSON := bytes.TrimSpace(raw)
	if len(trimmedJSON) > 0 && trimmedJSON[0] == '{' {
		if trimmedJSON[len(trimmedJSON)-1] == '}' {
			ev, ok := parseJSONLine(id, trimmedJSON, maxLineLen, defaultService)
			if ok {
				return ev, nil
			}
		}
		if len(raw) > maxLineLen {
			return model.LogEvent{}, fmt.Errorf("%w: malformed oversized JSON record (%d bytes)", ErrOversizedLine, len(raw))
		}
	}

	// Bound non-JSON lines safely before format parsing.
	if len(raw) > maxLineLen {
		raw = truncateUTF8Bytes(raw, maxLineLen)
	}

	// 2. Syslog RFC 5424 / 3164
	if raw[0] == '<' {
		idxClose := bytes.IndexByte(raw, '>')
		if idxClose > 1 && idxClose <= 5 {
			return parseSyslog(id, raw, idxClose, defaultService), nil
		}
	}

	// 3. Pipe format: <timestamp>|<service>|<level>|<trace_id>|<message>
	idx1 := bytes.IndexByte(raw, '|')
	if idx1 > 0 && isAllDigits(raw[:idx1]) {
		if ev, err := parsePipeLine(id, raw); err == nil {
			return ev, nil
		}
	}

	// 4. Plain text fallback (preserves original untrimmed whitespace)
	return parsePlainText(id, raw, defaultService), nil
}

func truncateUTF8Bytes(b []byte, maxBytes int) []byte {
	if len(b) <= maxBytes {
		return b
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(b[cut]) {
		cut--
	}
	return b[:cut]
}

func truncateUTF8String(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func isAllDigits(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func parsePipeLine(id uint64, raw []byte) (model.LogEvent, error) {
	idx1 := bytes.IndexByte(raw, '|')
	if idx1 <= 0 {
		return model.LogEvent{}, errors.New("malformed pipe line")
	}
	ts, err := strconv.ParseInt(string(raw[:idx1]), 10, 64)
	if err != nil {
		return model.LogEvent{}, err
	}
	rest := raw[idx1+1:]

	idx2 := bytes.IndexByte(rest, '|')
	if idx2 == -1 {
		return model.LogEvent{}, errors.New("malformed pipe line")
	}
	service := string(rest[:idx2])
	rest = rest[idx2+1:]

	idx3 := bytes.IndexByte(rest, '|')
	if idx3 == -1 {
		return model.LogEvent{}, errors.New("malformed pipe line")
	}
	level := normalizeLevel(string(rest[:idx3]))
	rest = rest[idx3+1:]

	idx4 := bytes.IndexByte(rest, '|')
	if idx4 == -1 {
		return model.LogEvent{}, errors.New("malformed pipe line")
	}
	tail := string(rest)
	traceID := tail[:idx4]
	msg := tail[idx4+1:]

	return model.LogEvent{
		ID:        id,
		Timestamp: ts,
		Service:   service,
		Level:     level,
		TraceID:   traceID,
		Message:   msg,
		SizeBytes: len(raw),
	}, nil
}

func parseJSONLine(id uint64, raw []byte, maxLineLen int, defaultService string) (model.LogEvent, bool) {
	var obj map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil || obj == nil {
		return model.LogEvent{}, false
	}

	var ts int64
	for _, k := range []string{"time", "ts", "timestamp", "@timestamp"} {
		if val, ok := obj[k]; ok {
			ts = parseTimestampValue(val)
			delete(obj, k)
			break
		}
	}
	if ts <= 0 {
		ts = time.Now().Unix()
	}

	var level string
	for _, k := range []string{"level", "severity", "lvl"} {
		if val, ok := obj[k]; ok {
			level = normalizeLevel(stringifyJSONValue(val))
			delete(obj, k)
			break
		}
	}
	if level == "" {
		level = "INFO"
	}

	var service string
	for _, k := range []string{"service", "app", "logger", "name"} {
		if val, ok := obj[k]; ok {
			service = stringifyJSONValue(val)
			delete(obj, k)
			break
		}
	}
	if service == "" {
		service = defaultService
	}

	var traceID string
	for _, k := range []string{"trace_id", "traceId", "trace"} {
		if val, ok := obj[k]; ok {
			traceID = stringifyJSONValue(val)
			delete(obj, k)
			break
		}
	}

	var message string
	for _, k := range []string{"msg", "message"} {
		if val, ok := obj[k]; ok {
			message = truncateUTF8String(stringifyJSONValue(val), maxLineLen)
			delete(obj, k)
			break
		}
	}

	var attrs map[string]string
	if len(obj) > 0 {
		attrs = make(map[string]string, len(obj))
		for k, v := range obj {
			attrs[k] = truncateUTF8String(stringifyJSONValue(v), maxLineLen)
		}
	}

	return model.LogEvent{
		ID:         id,
		Timestamp:  ts,
		Service:    service,
		Level:      level,
		TraceID:    traceID,
		Message:    message,
		Attributes: attrs,
		SizeBytes:  len(raw),
	}, true
}

func stringifyJSONValue(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case map[string]any, []any:
		b, _ := json.Marshal(t)
		return string(b)
	default:
		return fmt.Sprint(t)
	}
}

func parseTimestampValue(val any) int64 {
	switch v := val.(type) {
	case json.Number:
		if n, err := v.Int64(); err == nil {
			if n > 1e12 {
				return n / 1000
			}
			return n
		}
		if f, err := v.Float64(); err == nil {
			n := int64(f)
			if n > 1e12 {
				return n / 1000
			}
			return n
		}
	case float64:
		n := int64(v)
		if n > 1e12 {
			return n / 1000
		}
		return n
	case int64:
		if v > 1e12 {
			return v / 1000
		}
		return v
	case string:
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t.Unix()
		}
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t.Unix()
		}
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			if n > 1e12 {
				return n / 1000
			}
			return n
		}
	}
	return 0
}

func normalizeLevel(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "DBG", "DEBUG", "TRACE":
		return "DEBUG"
	case "INF", "INFO", "NOTICE":
		return "INFO"
	case "WRN", "WARN", "WARNING":
		return "WARN"
	case "ERR", "ERROR":
		return "ERROR"
	case "CRIT", "CRITICAL", "FATAL", "EMERG", "EMERGENCY", "PANIC":
		return "FATAL"
	default:
		if s == "" {
			return "INFO"
		}
		return s
	}
}

func parseSyslog(id uint64, raw []byte, idxClose int, defaultService string) model.LogEvent {
	pri, err := strconv.Atoi(string(raw[1:idxClose]))
	if err != nil || pri < 0 {
		return parsePlainText(id, raw, defaultService)
	}
	level := syslogSeverityMap[pri&7]
	rest := bytes.TrimSpace(raw[idxClose+1:])

	if bytes.HasPrefix(rest, []byte("1 ")) {
		return parseSyslogRFC5424(id, rest[2:], level, defaultService, len(raw))
	}
	return parseSyslogRFC3164(id, rest, level, defaultService, len(raw))
}

func parseSyslogRFC5424(id uint64, rest []byte, level, defaultService string, rawLen int) model.LogEvent {
	parts := strings.SplitN(string(rest), " ", 6)
	if len(parts) < 6 {
		ev := parsePlainText(id, rest, defaultService)
		ev.Level = level
		return ev
	}
	tsStr, appName, msgID, msg := parts[0], parts[2], parts[4], parts[5]

	var ts int64
	if t, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
		ts = t.Unix()
	} else if t, err := time.Parse(time.RFC3339, tsStr); err == nil {
		ts = t.Unix()
	} else {
		ts = time.Now().Unix()
	}

	service := appName
	if service == "-" || service == "" {
		service = defaultService
	}
	traceID := msgID
	if traceID == "-" {
		traceID = ""
	}
	msg = stripRFC5424StructuredData(msg)

	return model.LogEvent{
		ID:        id,
		Timestamp: ts,
		Service:   service,
		Level:     level,
		TraceID:   traceID,
		Message:   msg,
		SizeBytes: rawLen,
	}
}

// stripRFC5424StructuredData consumes either NILVALUE ("-") or all adjacent
// [sd-id param="val"] structured-data elements, honoring RFC 5424 backslash
// escapes inside quoted parameter values (`\"`, `\\`, `\]`).
func stripRFC5424StructuredData(s string) string {
	if s == "-" {
		return ""
	}
	if strings.HasPrefix(s, "- ") {
		return strings.TrimSpace(s[2:])
	}
	if !strings.HasPrefix(s, "[") {
		return s
	}

	i := 0
	for i < len(s) && s[i] == '[' {
		i++ // skip '['
		inQuotes := false
		escaped := false
		closed := false
		for i < len(s) {
			c := s[i]
			i++
			if escaped {
				escaped = false
				continue
			}
			if inQuotes {
				if c == '\\' {
					escaped = true
				} else if c == '"' {
					inQuotes = false
				}
				continue
			}
			if c == '"' {
				inQuotes = true
			} else if c == ']' {
				closed = true
				break
			}
		}
		if !closed {
			return s
		}
	}
	return strings.TrimSpace(s[i:])
}

func parseSyslogRFC3164(id uint64, rest []byte, level, defaultService string, rawLen int) model.LogEvent {
	s := string(rest)
	if len(s) < 16 {
		ev := parsePlainText(id, rest, defaultService)
		ev.Level = level
		return ev
	}

	now := time.Now()
	ts := now.Unix()
	if t, err := time.ParseInLocation("Jan _2 15:04:05", s[:15], now.Location()); err == nil {
		ts = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, now.Location()).Unix()
	}

	remainder := strings.TrimSpace(s[15:])
	service := defaultService
	msg := remainder
	if idxColon := strings.Index(remainder, ":"); idxColon != -1 {
		prefix := strings.TrimSpace(remainder[:idxColon])
		msg = strings.TrimSpace(remainder[idxColon+1:])
		fields := strings.Fields(prefix)
		if len(fields) > 0 {
			tag := fields[len(fields)-1]
			if idxBracket := strings.IndexByte(tag, '['); idxBracket > 0 {
				tag = tag[:idxBracket]
			}
			if tag != "" {
				service = tag
			}
		}
	}

	return model.LogEvent{
		ID:        id,
		Timestamp: ts,
		Service:   service,
		Level:     level,
		Message:   msg,
		SizeBytes: rawLen,
	}
}

func parsePlainText(id uint64, raw []byte, defaultService string) model.LogEvent {
	s := string(raw)
	upper := strings.ToUpper(s)
	level := "INFO"
	switch {
	case strings.Contains(upper, "FATAL") || strings.Contains(upper, "PANIC") || strings.Contains(upper, "CRIT"):
		level = "FATAL"
	case strings.Contains(upper, "ERROR") || strings.Contains(upper, "ERR") || strings.Contains(upper, "EXCEPTION"):
		level = "ERROR"
	case strings.Contains(upper, "WARN") || strings.Contains(upper, "WARNING"):
		level = "WARN"
	case strings.Contains(upper, "DEBUG") || strings.Contains(upper, "TRACE"):
		level = "DEBUG"
	}

	return model.LogEvent{
		ID:        id,
		Timestamp: time.Now().Unix(),
		Service:   defaultService,
		Level:     level,
		Message:   s,
		SizeBytes: len(raw),
	}
}
