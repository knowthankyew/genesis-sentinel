package ingest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
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
	if len(bytes.TrimSpace(raw)) == 0 {
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

	// 2. Pipe format: parse BEFORE maxLineLen truncation so a long trace_id or message
	// cannot lose the fourth '|' delimiter and relabel service=sentinel as plain text.
	if idx1 := bytes.IndexByte(raw, '|'); idx1 > 0 && isAllDigits(raw[:idx1]) {
		ev, pipeErr := parsePipeLine(id, raw, maxLineLen)
		if pipeErr == nil {
			return ev, nil
		}
		if errors.Is(pipeErr, ErrOversizedLine) || len(raw) > maxLineLen {
			return model.LogEvent{}, fmt.Errorf("%w: malformed or oversized pipe record (%d bytes)", ErrOversizedLine, len(raw))
		}
	}

	// 3. Syslog RFC 5424 & RFC 3164: parse structured headers BEFORE maxLineLen truncation
	// so a long hostname or small maxLineLen cannot truncate APP-NAME / TAG (e.g. service=sentinel)
	// and relabel the record as plain text with defaultService.
	if raw[0] == '<' {
		idxClose := bytes.IndexByte(raw, '>')
		if idxClose > 1 && idxClose <= 5 {
			if pri, err := strconv.Atoi(string(raw[1:idxClose])); err == nil && pri >= 0 {
				level := syslogSeverityMap[pri&7]
				rest := bytes.TrimLeft(raw[idxClose+1:], " \t")
				if bytes.HasPrefix(rest, []byte("1 ")) {
					ev, rfcErr := parseSyslogRFC5424Bounded(id, rest[2:], level, defaultService, len(raw), maxLineLen)
					if rfcErr == nil {
						return ev, nil
					}
					if errors.Is(rfcErr, ErrOversizedLine) || len(raw) > maxLineLen {
						return model.LogEvent{}, fmt.Errorf("%w: malformed or oversized RFC 5424 record (%d bytes)", ErrOversizedLine, len(raw))
					}
				} else if ev, rfcErr := parseSyslogRFC3164Bounded(id, bytes.TrimSpace(rest), level, defaultService, len(raw), maxLineLen); rfcErr == nil {
					return ev, nil
				} else if errors.Is(rfcErr, ErrOversizedLine) || len(raw) > maxLineLen {
					return model.LogEvent{}, fmt.Errorf("%w: malformed or oversized RFC 3164 record (%d bytes)", ErrOversizedLine, len(raw))
				}
			}
		}
	}

	// Bound remaining non-JSON/non-pipe/non-syslog lines safely before format parsing.
	if len(raw) > maxLineLen {
		raw = truncateUTF8Bytes(raw, maxLineLen)
		if len(bytes.TrimSpace(raw)) == 0 {
			return model.LogEvent{}, ErrEmptyInput
		}
	}

	// 4. Short/fallback syslog
	if raw[0] == '<' {
		idxClose := bytes.IndexByte(raw, '>')
		if idxClose > 1 && idxClose <= 5 {
			return parseSyslog(id, raw, idxClose, defaultService), nil
		}
	}

	// 5. Plain text fallback (preserves original untrimmed whitespace)
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

// truncateUTF8String clones the bounded prefix so truncating a large decoded string
// does not pin a multi-hundred-KiB backing allocation in memory.
func truncateUTF8String(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.Clone(s[:cut])
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

func parsePipeLine(id uint64, raw []byte, maxLineLen int) (model.LogEvent, error) {
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
	// Reject oversized structured metadata prefix rather than truncating fields.
	headerLen := idx1 + 1 + idx2 + 1 + idx3 + 1 + idx4
	if headerLen > maxLineLen {
		return model.LogEvent{}, fmt.Errorf("%w: pipe metadata header (%d bytes) exceeds %d", ErrOversizedLine, headerLen, maxLineLen)
	}
	traceID := string(rest[:idx4])
	msgBytes := truncateUTF8Bytes(rest[idx4+1:], maxLineLen)
	msg := string(msgBytes)

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
	// Require EOF after the single JSON object so trailing non-whitespace text or a second object is rejected.
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
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

func floatToUnixSec(f float64) (int64, bool) {
	// Reject NaN, +/-Inf, non-positive values, and magnitudes outside safe int64 range.
	const maxSafeFloat = float64(math.MaxInt64 / 2)
	if math.IsNaN(f) || math.IsInf(f, 0) || f <= 0 || f > maxSafeFloat {
		return 0, false
	}
	n := int64(f)
	if n > 1e12 {
		return n / 1000, true
	}
	return n, true
}

func parseTimestampValue(val any) int64 {
	switch v := val.(type) {
	case json.Number:
		if n, err := v.Int64(); err == nil {
			if n <= 0 {
				return 0
			}
			if n > 1e12 {
				return n / 1000
			}
			return n
		}
		if f, err := v.Float64(); err == nil {
			if n, ok := floatToUnixSec(f); ok {
				return n
			}
		}
	case float64:
		if n, ok := floatToUnixSec(v); ok {
			return n
		}
	case int64:
		if v <= 0 {
			return 0
		}
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
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
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
	// Trim only leading spaces/tabs after PRI so trailing message bytes are preserved for RFC 5424.
	rest := bytes.TrimLeft(raw[idxClose+1:], " \t")

	if bytes.HasPrefix(rest, []byte("1 ")) {
		return parseSyslogRFC5424(id, rest[2:], level, defaultService, len(raw))
	}
	return parseSyslogRFC3164(id, bytes.TrimSpace(rest), level, defaultService, len(raw))
}

func parseSyslogRFC5424Bounded(id uint64, rest []byte, level, defaultService string, rawLen, maxLineLen int) (model.LogEvent, error) {
	const (
		maxRFC5424TimestampBytes = 64
		maxRFC5424HostnameBytes  = 1024
		maxRFC5424AppNameBytes   = 256
		maxRFC5424ProcIDBytes    = 256
		maxRFC5424MsgIDBytes     = 256
	)
	parts := strings.SplitN(string(rest), " ", 6)
	if len(parts) < 6 {
		if rawLen > maxLineLen {
			return model.LogEvent{}, ErrOversizedLine
		}
		ev := parsePlainText(id, rest, defaultService)
		ev.Level = level
		return ev, nil
	}
	tsStr, hostname, appName, procID, msgID, msg := parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
	if len(tsStr) > maxRFC5424TimestampBytes ||
		len(hostname) > maxRFC5424HostnameBytes ||
		len(appName) > maxRFC5424AppNameBytes ||
		len(procID) > maxRFC5424ProcIDBytes ||
		len(msgID) > maxRFC5424MsgIDBytes {
		return model.LogEvent{}, ErrOversizedLine
	}

	var ts int64
	if t, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
		ts = t.Unix()
	} else if t, err := time.Parse(time.RFC3339, tsStr); err == nil {
		ts = t.Unix()
	} else {
		ts = time.Now().Unix()
	}

	service := strings.Clone(appName)
	if service == "-" || service == "" {
		service = defaultService
	}
	traceID := strings.Clone(msgID)
	if traceID == "-" {
		traceID = ""
	}
	msg = stripRFC5424StructuredData(msg)
	if len(msg) > maxLineLen {
		msg = truncateUTF8String(msg, maxLineLen)
	} else {
		msg = strings.Clone(msg)
	}

	return model.LogEvent{
		ID:        id,
		Timestamp: ts,
		Service:   service,
		Level:     level,
		TraceID:   traceID,
		Message:   msg,
		SizeBytes: rawLen,
	}, nil
}

func parseSyslogRFC5424(id uint64, rest []byte, level, defaultService string, rawLen int) model.LogEvent {
	ev, err := parseSyslogRFC5424Bounded(id, rest, level, defaultService, rawLen, DefaultMaxLineLength)
	if err != nil {
		fallback := parsePlainText(id, rest, defaultService)
		fallback.Level = level
		return fallback
	}
	return ev
}

// stripRFC5424StructuredData consumes either NILVALUE ("-") or all adjacent
// [sd-id param="val"] structured-data elements, honoring RFC 5424 backslash
// escapes inside quoted parameter values (`\"`, `\\`, `\]`) and removing only
// the single protocol SP separator before MSG so message whitespace is preserved.
func stripRFC5424StructuredData(s string) string {
	if s == "-" {
		return ""
	}
	if strings.HasPrefix(s, "- ") {
		return s[2:]
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
	if i == len(s) {
		return ""
	}
	if s[i] == ' ' {
		return s[i+1:]
	}
	return s[i:]
}

func parseSyslogRFC3164Bounded(id uint64, rest []byte, level, defaultService string, rawLen, maxLineLen int) (model.LogEvent, error) {
	const maxRFC3164HostnameBytes = 1024
	s := string(rest)
	if len(s) < 16 {
		if rawLen > maxLineLen {
			return model.LogEvent{}, ErrOversizedLine
		}
		ev := parsePlainText(id, rest, defaultService)
		ev.Level = level
		return ev, nil
	}

	now := time.Now()
	t, tsErr := time.ParseInLocation("Jan _2 15:04:05", s[:15], now.Location())
	if tsErr != nil {
		if rawLen > maxLineLen {
			return model.LogEvent{}, ErrOversizedLine
		}
		ev := parsePlainText(id, rest, defaultService)
		ev.Level = level
		return ev, nil
	}
	// RFC 3164 omits year: infer current year, rolling back to now.Year()-1 if the
	// inferred timestamp falls more than 24h in the future (e.g. Dec 31 log read on Jan 1).
	inferred := time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, now.Location())
	if inferred.After(now.Add(24 * time.Hour)) {
		inferred = time.Date(now.Year()-1, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, now.Location())
	}
	ts := inferred.Unix()

	remainder := strings.TrimSpace(s[15:])
	service := defaultService
	msg := remainder

	// RFC 3164 layout after timestamp: HOSTNAME MSG (where MSG begins with alphanumeric TAG + non-alphanumeric delimiter + CONTENT).
	// Recognize IPv6 literals (including ones ending in "::" like 2001:db8::) and hostname-free
	// TAGs (colon-terminated, PID-bracketed like "sentinel[42]", or non-hostname content delimited
	// like "sentinel(alert)") before stripping an optional hostname.
	if spIdx := strings.IndexByte(remainder, ' '); spIdx != -1 {
		firstWord := remainder[:spIdx]
		afterHost := strings.TrimSpace(remainder[spIdx+1:])
		isIPv6Host := net.ParseIP(strings.Trim(firstWord, "[]")) != nil
		isTagWord := strings.HasSuffix(firstWord, ":") || isPIDTaggedSyslogWord(firstWord) || hasNonHostnameContentDelimiter(firstWord)
		if (isIPv6Host || !isTagWord) && afterHost != "" {
			if len(firstWord) > maxRFC3164HostnameBytes {
				return model.LogEvent{}, ErrOversizedLine
			}
			remainder = afterHost
		}
	}

	if tag, body, ok := splitRFC3164Tag(remainder); ok {
		service = strings.Clone(tag)
		msg = body
	} else if rawLen > maxLineLen {
		return model.LogEvent{}, ErrOversizedLine
	}

	if len(msg) > maxLineLen {
		msg = truncateUTF8String(msg, maxLineLen)
	} else {
		msg = strings.Clone(msg)
	}

	return model.LogEvent{
		ID:        id,
		Timestamp: ts,
		Service:   service,
		Level:     level,
		Message:   msg,
		SizeBytes: rawLen,
	}, nil
}

func parseSyslogRFC3164(id uint64, rest []byte, level, defaultService string, rawLen int) model.LogEvent {
	ev, err := parseSyslogRFC3164Bounded(id, rest, level, defaultService, rawLen, DefaultMaxLineLength)
	if err != nil {
		fallback := parsePlainText(id, rest, defaultService)
		fallback.Level = level
		return fallback
	}
	return ev
}

// splitRFC3164Tag extracts the leading RFC 3164 §4.1.3 alphanumeric program TAG (up to
// 32 ASCII alphanumeric characters, stripping optional numeric [PID]) delimited by ':',
// space, or any other non-alphanumeric CONTENT starter (such as '(' or '.').
func splitRFC3164Tag(remainder string) (string, string, bool) {
	if remainder == "" {
		return "", "", false
	}
	// 1. Prefer colon delimiter if it appears before the first space (e.g. "sudo[991]: msg" or "sshd: msg").
	firstSpace := strings.IndexByte(remainder, ' ')
	firstColon := strings.IndexByte(remainder, ':')
	if firstColon > 0 && (firstSpace == -1 || firstColon < firstSpace) {
		rawTag := remainder[:firstColon]
		tag := stripPIDBracket(rawTag)
		if isValidRFC3164Tag(tag) {
			return tag, strings.TrimSpace(remainder[firstColon+1:]), true
		}
	}
	// 2. Space-delimited tag without colon (e.g. "sentinel[42] alert emitted" or "cronjob completed ok").
	if firstSpace > 0 {
		rawTag := remainder[:firstSpace]
		tag := stripPIDBracket(rawTag)
		if isValidRFC3164Tag(tag) {
			return tag, strings.TrimSpace(remainder[firstSpace+1:]), true
		}
	}
	// 3. Any other RFC 3164 §4.1.3 non-alphanumeric delimiter starting CONTENT (e.g. "sentinel(alert)", "sentinel.alert", "sshd[notice: failed]").
	delimIdx := firstNonAlnumByte(remainder)
	if delimIdx > 0 && delimIdx < len(remainder) {
		tag := remainder[:delimIdx]
		if isValidRFC3164Tag(tag) {
			rest := remainder[delimIdx:]
			if rest[0] == '[' {
				if closeIdx := strings.IndexByte(rest, ']'); closeIdx > 1 && isAllDigits([]byte(rest[1:closeIdx])) {
					rest = rest[closeIdx+1:]
					if strings.HasPrefix(rest, ":") {
						rest = strings.TrimSpace(rest[1:])
					} else if strings.HasPrefix(rest, " ") {
						rest = strings.TrimSpace(rest[1:])
					}
				}
			}
			return tag, rest, true
		}
	}
	return "", "", false
}

func firstNonAlnumByte(s string) int {
	for i := 0; i < len(s); i++ {
		if !isASCIIAlnum(s[i]) {
			return i
		}
	}
	return len(s)
}

// hasNonHostnameContentDelimiter reports whether word starts with an RFC 3164 alphanumeric TAG
// followed by a non-hostname delimiter (excluding DNS hostname characters '-' and '.').
func hasNonHostnameContentDelimiter(word string) bool {
	delimIdx := firstNonAlnumByte(word)
	if delimIdx <= 0 || delimIdx >= len(word) || !isValidRFC3164Tag(word[:delimIdx]) {
		return false
	}
	c := word[delimIdx]
	return c != '-' && c != '.'
}

// stripPIDBracket strips a trailing bracketed numeric "[PID]" suffix from rawTag.
// Bracketed non-numeric CONTENT (such as "sshd[notice" in "sshd[notice: failed]")
// is left intact so RFC 3164 CONTENT starting with '[' is never mangled.
func stripPIDBracket(rawTag string) string {
	idx := strings.IndexByte(rawTag, '[')
	if idx <= 0 || !strings.HasSuffix(rawTag, "]") {
		return rawTag
	}
	pid := rawTag[idx+1 : len(rawTag)-1]
	if len(pid) == 0 || !isAllDigits([]byte(pid)) {
		return rawTag
	}
	return rawTag[:idx]
}

// isPIDTaggedSyslogWord reports whether word is a hostname-free RFC 3164 TAG with a
// bracketed numeric PID (e.g. "sentinel[42]" or "sshd[1234]:").
func isPIDTaggedSyslogWord(word string) bool {
	trimmed := strings.TrimSuffix(word, ":")
	openIdx := strings.IndexByte(trimmed, '[')
	if openIdx <= 0 || !strings.HasSuffix(trimmed, "]") {
		return false
	}
	tag := trimmed[:openIdx]
	pid := trimmed[openIdx+1 : len(trimmed)-1]
	if !isValidRFC3164Tag(tag) || len(pid) == 0 {
		return false
	}
	for i := 0; i < len(pid); i++ {
		if pid[i] < '0' || pid[i] > '9' {
			return false
		}
	}
	return true
}

func isASCIIAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

func isValidRFC3164Tag(tag string) bool {
	if len(tag) == 0 || len(tag) > 32 {
		return false
	}
	for i := 0; i < len(tag); i++ {
		if !isASCIIAlnum(tag[i]) {
			return false
		}
	}
	return true
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
