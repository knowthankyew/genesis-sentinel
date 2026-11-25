package feedback

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/knowthankyew/genesis-sentinel/internal/security"
)

var (
	// PEM private key blocks (complete single/multi-line blocks and truncated unterminated blocks).
	pemPrivateKeyRe             = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	pemPrivateKeyUnterminatedRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*`)

	// JWT candidates (3 base64url segments beginning with eyJ; validated structurally in Go
	// so compact tokens with short claims objects such as e30 ("{}") are caught without false positives).
	jwtCandidateRe = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{8,}\b`)

	// Connection/HTTP URL scheme prefixes for scrubbing embedded user:pass@host credentials.
	urlSchemeRe = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]{1,15}://`)

	// Authorization Bearer and Basic credentials (both plain headers and JSON-quoted header keys).
	authHeaderCredRe = regexp.MustCompile(`(?i)(["']?)\b((?:Proxy-)?Authorization)(["']?\s*[:=]\s*["']?(?:Bearer|Basic)\s+)([A-Za-z0-9._~+/=-]{4,})`)
	bearerRe         = regexp.MustCompile(`(?i)\b(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})`)
	basicTokenRe     = regexp.MustCompile(`(?i)\b(Basic\s+)([A-Za-z0-9+/]{4,}={0,2})`)

	// Credential-bearing *_AUTH_CONFIG keys (e.g., DOCKER_AUTH_CONFIG JSON objects or strings).
	authConfigKeyRe = regexp.MustCompile(`(?i)(["']?)\b([A-Z0-9_-]*auth[_-]?config)(["']?\s*[=:]\s*)`)

	// Common cloud, VCS, and AI API key prefixes.
	apiKeyPrefixRe = regexp.MustCompile(`\b(?:(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b`)

	// Credential key=value or key: value assignment prefixes (both bare keys such as password=
	// and prefixed env/config keys such as DB_PASSWORD=, REDIS_AUTH_TOKEN=, API_SECRET=).
	// Values are consumed by the quote-aware scanner below so adjacent quoted segments and
	// unterminated quotes are fully masked.
	credKVKeyRe = regexp.MustCompile(`(?i)(["']?)\b((?:[A-Za-z0-9_-]+[_-])?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key))(["']?\s*[=:]\s*)`)

	// Email addresses.
	emailRe = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)

	// Delimited SSN candidates (validated against SSA area/group/serial rules in Go code
	// because Go RE2 intentionally omits negative lookahead).
	ssnDelimitedCandidateRe = regexp.MustCompile(`\b(\d{3})([- ])(\d{2})([- ])(\d{4})\b`)

	// Contextual SSN candidates preceded by "ssn" or "social security".
	ssnContextualCandidateRe = regexp.MustCompile(`(?i)\b(ssn|social\s*security(?:\s*number)?)([^\d]{1,10})(\d{3})([- ]?)(\d{2})([- ]?)(\d{4})\b`)

	// Credit/debit card digit candidates (13-19 digits, contiguous or standard groupings
	// including 4-4-4-4, 4-6-5 Amex, 4-6-4 Diners, 4-4-4-1..3, and 4-4-4-4-1..3; validated via Luhn).
	cardCandidateRe = regexp.MustCompile(`\b(?:\d{4}[ -]\d{6}[ -]\d{4,5}|\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}(?:[ -]\d{1,3})?|\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,3}|\d{13,19})\b`)
)

// RedactText neutralizes chat-template delimiters and scrubs PII/secrets (PEM private keys,
// JWTs, Bearer/Basic authorization credentials, cloud/VCS API keys, unquoted and quoted
// credential key=value pairs, emails, SSA-valid SSNs, and Luhn-valid payment cards) before
// any log text enters alerts.jsonl, sinks, or FTaaS JSONL datasets.
// Returns the scrubbed string and deduplicated list of redacted categories.
func RedactText(raw string) (string, []string) {
	if raw == "" {
		return "", nil
	}

	// Neutralize chat-template tokens without truncating valid long prompts or multi-line PEM
	// blocks even if invalid UTF-8 bytes expand to 3-byte replacement runes during sanitization.
	s, _ := security.SanitizeUntrustedLogText(raw, len(raw)*3+64)

	var findings []string
	seen := make(map[string]struct{}, 4)
	addFinding := func(name string) {
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			findings = append(findings, name)
		}
	}

	if pemPrivateKeyRe.MatchString(s) {
		s = pemPrivateKeyRe.ReplaceAllString(s, "[REDACTED_PRIVATE_KEY]")
		addFinding("private_key")
	}
	if pemPrivateKeyUnterminatedRe.MatchString(s) {
		s = pemPrivateKeyUnterminatedRe.ReplaceAllString(s, "[REDACTED_PRIVATE_KEY]")
		addFinding("private_key")
	}
	s = jwtCandidateRe.ReplaceAllStringFunc(s, func(match string) string {
		if !looksLikeCompactJWT(match) {
			return match
		}
		addFinding("jwt")
		return "[REDACTED_JWT]"
	})
	if next, changed := redactURLCredentials(s); changed {
		s = next
		addFinding("url_credential")
	}
	if authHeaderCredRe.MatchString(s) {
		s = authHeaderCredRe.ReplaceAllString(s, "${1}${2}${3}[REDACTED_TOKEN]")
		addFinding("auth_credential")
	}
	if next, changed := redactAuthConfigValues(s); changed {
		s = next
		addFinding("auth_config")
	}
	if bearerRe.MatchString(s) {
		s = bearerRe.ReplaceAllString(s, "${1}[REDACTED_TOKEN]")
		addFinding("bearer_token")
	}
	s = basicTokenRe.ReplaceAllStringFunc(s, func(match string) string {
		sub := basicTokenRe.FindStringSubmatch(match)
		if len(sub) < 3 || !looksLikeEncodedBasicCred(sub[2]) {
			return match
		}
		addFinding("basic_auth")
		return sub[1] + "[REDACTED_TOKEN]"
	})
	if apiKeyPrefixRe.MatchString(s) {
		s = apiKeyPrefixRe.ReplaceAllString(s, "[REDACTED_API_KEY]")
		addFinding("api_key")
	}
	if next, changed := redactCredKVValues(s); changed {
		s = next
		addFinding("credential_value")
	}
	if emailRe.MatchString(s) {
		s = emailRe.ReplaceAllString(s, "[REDACTED_EMAIL]")
		addFinding("email")
	}
	s = ssnContextualCandidateRe.ReplaceAllStringFunc(s, func(match string) string {
		sub := ssnContextualCandidateRe.FindStringSubmatch(match)
		if len(sub) < 8 || !isValidSSAParts(sub[3], sub[5], sub[7]) {
			return match
		}
		addFinding("ssn")
		return sub[1] + sub[2] + "[REDACTED_SSN]"
	})
	s = ssnDelimitedCandidateRe.ReplaceAllStringFunc(s, func(match string) string {
		sub := ssnDelimitedCandidateRe.FindStringSubmatch(match)
		if len(sub) < 6 || !isValidSSAParts(sub[1], sub[3], sub[5]) {
			return match
		}
		addFinding("ssn")
		return "[REDACTED_SSN]"
	})
	if next, changed := redactCards(s); changed {
		s = next
		addFinding("payment_card")
	}

	return s, findings
}

// ScanForPII performs a fail-closed pre-export compliance scan mirroring FTaaS's
// DatasetService.ScanForPii (SSA-valid SSNs and Luhn-valid payment cards) plus high-risk
// unredacted secret/PII patterns (PEM private keys, JWTs, connection URL credentials,
// Bearer/Basic authorization credentials, *_AUTH_CONFIG secrets, credential KV assignments,
// emails, and cloud/VCS API keys).
func ScanForPII(text string) (string, bool) {
	if strings.TrimSpace(text) == "" {
		return "", false
	}
	if pemPrivateKeyRe.MatchString(text) || pemPrivateKeyUnterminatedRe.MatchString(text) {
		return "PEM Private Key", true
	}
	for _, tok := range jwtCandidateRe.FindAllString(text, -1) {
		if looksLikeCompactJWT(tok) {
			return "JWT Bearer Token", true
		}
	}
	if hasURLCredentials(text) {
		return "URL Credential", true
	}
	if authHeaderCredRe.MatchString(text) {
		return "Authorization Credential", true
	}
	if hasUnredactedAuthConfig(text) {
		return "Auth Configuration Secret", true
	}
	if bearerRe.MatchString(text) {
		return "Bearer Token", true
	}
	for _, sub := range basicTokenRe.FindAllStringSubmatch(text, -1) {
		if len(sub) >= 3 && looksLikeEncodedBasicCred(sub[2]) {
			return "Basic Auth Credential", true
		}
	}
	if apiKeyPrefixRe.MatchString(text) {
		return "API Access Key", true
	}
	if hasUnredactedCredKV(text) {
		return "Credential Assignment", true
	}
	if emailRe.MatchString(text) {
		return "Email Address", true
	}
	for _, sub := range ssnContextualCandidateRe.FindAllStringSubmatch(text, -1) {
		if len(sub) >= 8 && isValidSSAParts(sub[3], sub[5], sub[7]) {
			return "Social Security Number (SSN)", true
		}
	}
	for _, sub := range ssnDelimitedCandidateRe.FindAllStringSubmatch(text, -1) {
		if len(sub) >= 6 && isValidSSAParts(sub[1], sub[3], sub[5]) {
			return "Social Security Number (SSN)", true
		}
	}
	if hasLuhnCard(text) {
		return "Credit/Debit Card Number", true
	}
	return "", false
}

// looksLikeCompactJWT validates that a 3-segment base64url JWT candidate decodes to JSON
// objects for both its header and claims segments (catching empty/short claims like "e30").
func looksLikeCompactJWT(tok string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return false
	}
	for i := 0; i < 2; i++ {
		decoded, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return false
		}
		trimmed := bytes.TrimSpace(decoded)
		if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
			return false
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return false
		}
	}
	return true
}

// redactURLCredentials scrubs scheme://user:pass@host credentials (including passwords that
// contain '@' by scanning to the last '@' inside the authority segment).
func redactURLCredentials(s string) (string, bool) {
	var b strings.Builder
	pos := 0
	changed := false
	for pos < len(s) {
		loc := urlSchemeRe.FindStringIndex(s[pos:])
		if loc == nil {
			b.WriteString(s[pos:])
			break
		}
		authStart := pos + loc[1]
		authEnd := authStart
		for authEnd < len(s) {
			ch := s[authEnd]
			// Preserve valid RFC 3986 userinfo punctuation (such as ';' and ',') during
			// authority scanning so passwords containing ';' or ',' still reach the last '@'.
			if ch <= ' ' || ch == '/' || ch == '?' || ch == '#' || ch == '"' || ch == '\'' || ch == '`' || ch == '<' || ch == '>' || ch == ')' || ch == ']' || ch == '}' {
				break
			}
			authEnd++
		}
		authority := s[authStart:authEnd]
		if atIdx := strings.LastIndexByte(authority, '@'); atIdx > 0 && atIdx < len(authority)-1 {
			hostPart := strings.TrimRight(authority[atIdx+1:], ",;")
			trailingPunct := len(authority[atIdx+1:]) - len(hostPart)
			userinfo := authority[:atIdx]
			if len(hostPart) > 0 && strings.ContainsRune(userinfo, ':') && !isRedactedPlaceholder(userinfo) {
				b.WriteString(s[pos:authStart])
				b.WriteString("[REDACTED_SECRET]@")
				b.WriteString(hostPart)
				pos = authEnd - trailingPunct
				changed = true
				continue
			}
		}
		b.WriteString(s[pos:authEnd])
		pos = authEnd
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

func hasURLCredentials(s string) bool {
	_, changed := redactURLCredentials(s)
	return changed
}

// redactCards performs a sliding-window Luhn card scan so a valid card following a non-card
// digit group (e.g. "batch 1234 4111 1111 1111 1111") is caught by advancing past only the
// first digit group when a candidate fails Luhn, while preserving trailing counts after valid cards.
func redactCards(s string) (string, bool) {
	var b strings.Builder
	pos := 0
	changed := false
	for pos < len(s) {
		loc := cardCandidateRe.FindStringIndex(s[pos:])
		if loc == nil {
			b.WriteString(s[pos:])
			break
		}
		start := pos + loc[0]
		end := pos + loc[1]
		match := s[start:end]
		if prefixEnd, ok := findCardLuhnMatch(match); ok {
			b.WriteString(s[pos:start])
			b.WriteString("[REDACTED_CARD]")
			pos = start + prefixEnd
			changed = true
			continue
		}
		if sep := strings.IndexAny(match, " -"); sep > 0 {
			nextPos := start + sep + 1
			b.WriteString(s[pos:nextPos])
			pos = nextPos
		} else {
			b.WriteString(s[pos:end])
			pos = end
		}
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

func hasLuhnCard(s string) bool {
	pos := 0
	for pos < len(s) {
		loc := cardCandidateRe.FindStringIndex(s[pos:])
		if loc == nil {
			return false
		}
		start := pos + loc[0]
		end := pos + loc[1]
		match := s[start:end]
		if _, ok := findCardLuhnMatch(match); ok {
			return true
		}
		if sep := strings.IndexAny(match, " -"); sep > 0 {
			pos = start + sep + 1
		} else {
			pos = end
		}
	}
	return false
}

// findCardLuhnMatch checks whether match is a Luhn-valid 13-19 digit payment card; if an
// extended 4-4-4-4-X match fails Luhn because a trailing space/hyphen-delimited count was
// consumed (e.g. "4111 1111 1111 1111 2 attempts"), it falls back to checking the 16-digit
// 4-4-4-4 prefix so valid 16-digit cards are never missed while genuine 17-19 digit cards work.
func findCardLuhnMatch(match string) (int, bool) {
	digits := stripNonDigits(match)
	if len(digits) >= 13 && len(digits) <= 19 && passesLuhn(digits) {
		return len(match), true
	}
	if len(digits) > 16 {
		if idx := strings.LastIndexAny(match, " -"); idx > 0 {
			prefix := match[:idx]
			pDigits := stripNonDigits(prefix)
			if len(pDigits) == 16 && passesLuhn(pDigits) {
				return idx, true
			}
		}
	}
	return 0, false
}

func isRedactedPlaceholder(val string) bool {
	switch val {
	case "",
		"[REDACTED]",
		"[REDACTED_SECRET]",
		"[REDACTED_TOKEN]",
		"[REDACTED_API_KEY]",
		"[REDACTED_JWT]",
		"[REDACTED_PRIVATE_KEY]",
		"[REDACTED_AUTH_CONFIG]",
		"[REDACTED_EMAIL]",
		"[REDACTED_SSN]",
		"[REDACTED_CARD]",
		"<STR>", "<HEX>", "<NUM>":
		return true
	default:
		return false
	}
}

func redactCredKVValues(s string) (string, bool) {
	var b strings.Builder
	pos := 0
	changed := false
	for pos < len(s) {
		loc := credKVKeyRe.FindStringIndex(s[pos:])
		if loc == nil {
			b.WriteString(s[pos:])
			break
		}
		valStart := pos + loc[1]
		b.WriteString(s[pos:valStart])
		valEnd, replacement, redacted := scanCredKVValue(s, valStart)
		if redacted {
			b.WriteString(replacement)
			changed = true
		} else {
			b.WriteString(s[valStart:valEnd])
		}
		if valEnd <= pos {
			pos = valStart + 1
		} else {
			pos = valEnd
		}
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

func hasUnredactedCredKV(text string) bool {
	pos := 0
	for pos < len(text) {
		loc := credKVKeyRe.FindStringIndex(text[pos:])
		if loc == nil {
			return false
		}
		valStart := pos + loc[1]
		valEnd, _, redacted := scanCredKVValue(text, valStart)
		if redacted {
			return true
		}
		if valEnd <= pos {
			pos = valStart + 1
		} else {
			pos = valEnd
		}
	}
	return false
}

// scanCredKVValue consumes a full quote-aware credential assignment word (including adjacent
// quoted sections such as password="a"'b' and unterminated quotes running to EOL), stopping
// at the first unquoted field delimiter while preserving exact [REDACTED_*] placeholders.
func scanCredKVValue(s string, valStart int) (int, string, bool) {
	if valStart >= len(s) {
		return valStart, "", false
	}
	i := valStart
	inQuote := byte(0)
	escaped := false
	for i < len(s) {
		ch := s[i]
		if inQuote != 0 {
			if ch == '\r' || ch == '\n' {
				break
			}
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == inQuote {
				inQuote = 0
			}
			i++
			continue
		}
		if ch == '"' || ch == '\'' {
			inQuote = ch
			i++
			continue
		}
		if ch == '[' && strings.HasPrefix(s[i:], "[REDACTED") {
			limit := min(len(s), i+32)
			closed := -1
			for j := i + len("[REDACTED"); j < limit; j++ {
				c := s[j]
				if c == ']' {
					closed = j + 1
					break
				}
				if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ';' || c == '&' || c == ',' || c == '}' {
					break
				}
			}
			if closed > 0 {
				i = closed
				continue
			}
		}
		if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ';' || ch == '&' || ch == ',' || ch == '}' || ch == ']' {
			break
		}
		i++
	}
	rawVal := s[valStart:i]
	if rawVal == "" {
		return i, "", false
	}
	if isRedactedPlaceholder(rawVal) {
		return i, rawVal, false
	}
	if len(rawVal) >= 2 && (rawVal[0] == '"' || rawVal[0] == '\'') && rawVal[len(rawVal)-1] == rawVal[0] {
		inner := rawVal[1 : len(rawVal)-1]
		if !strings.ContainsRune(inner, rune(rawVal[0])) && isRedactedPlaceholder(inner) {
			return i, rawVal, false
		}
	}
	if rawVal[0] == '"' {
		return i, `"[REDACTED_SECRET]"`, true
	}
	if rawVal[0] == '\'' {
		return i, `'[REDACTED_SECRET]'`, true
	}
	return i, "[REDACTED_SECRET]", true
}

// redactAuthConfigValues replaces credential-bearing *_AUTH_CONFIG values (such as
// DOCKER_AUTH_CONFIG={...} or JSON-quoted values) cleanly with [REDACTED_AUTH_CONFIG].
func redactAuthConfigValues(s string) (string, bool) {
	var b strings.Builder
	pos := 0
	changed := false
	for pos < len(s) {
		loc := authConfigKeyRe.FindStringIndex(s[pos:])
		if loc == nil {
			b.WriteString(s[pos:])
			break
		}
		valStart := pos + loc[1]
		b.WriteString(s[pos:valStart])
		valEnd, replacement, redacted := scanAuthConfigValue(s, valStart)
		if redacted {
			b.WriteString(replacement)
			changed = true
		} else {
			b.WriteString(s[valStart:valEnd])
		}
		pos = valEnd
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

func hasUnredactedAuthConfig(s string) bool {
	pos := 0
	for pos < len(s) {
		loc := authConfigKeyRe.FindStringIndex(s[pos:])
		if loc == nil {
			return false
		}
		valStart := pos + loc[1]
		valEnd, _, redacted := scanAuthConfigValue(s, valStart)
		if redacted {
			return true
		}
		if valEnd <= pos {
			pos = valStart + 1
		} else {
			pos = valEnd
		}
	}
	return false
}

// scanAuthConfigValue scans a JSON object ({...}), escape-aware quoted string, or unquoted
// value starting at s[valStart:] and reports its end index and redacted replacement.
func scanAuthConfigValue(s string, valStart int) (int, string, bool) {
	if valStart >= len(s) {
		return valStart, "", false
	}
	switch s[valStart] {
	case '{':
		depth := 0
		inQuote := byte(0)
		escaped := false
		i := valStart
		for i < len(s) {
			ch := s[i]
			if inQuote != 0 {
				if escaped {
					escaped = false
				} else if ch == '\\' {
					escaped = true
				} else if ch == inQuote {
					inQuote = 0
				}
			} else {
				switch ch {
				case '"', '\'':
					inQuote = ch
				case '{':
					depth++
				case '}':
					depth--
					if depth == 0 {
						return i + 1, "[REDACTED_AUTH_CONFIG]", true
					}
				}
			}
			i++
		}
		// Unterminated object: consume the full remaining suffix rather than leaking trailing fields.
		return len(s), "[REDACTED_AUTH_CONFIG]", true
	case '"', '\'':
		q := s[valStart]
		escaped := false
		i := valStart + 1
		for i < len(s) {
			ch := s[i]
			if ch == '\r' || ch == '\n' {
				break
			}
			if escaped {
				escaped = false
			} else if ch == '\\' {
				escaped = true
			} else if ch == q {
				inner := s[valStart+1 : i]
				if isRedactedPlaceholder(inner) {
					return i + 1, s[valStart : i+1], false
				}
				return i + 1, string(q) + "[REDACTED_AUTH_CONFIG]" + string(q), true
			}
			i++
		}
		inner := s[valStart+1 : i]
		if isRedactedPlaceholder(inner) {
			return i, s[valStart:i], false
		}
		return i, string(q) + "[REDACTED_AUTH_CONFIG]" + string(q), true
	default:
		i := valStart
		if strings.HasPrefix(s[valStart:], "[REDACTED") {
			limit := min(len(s), valStart+32)
			for j := valStart + len("[REDACTED"); j < limit; j++ {
				ch := s[j]
				if ch == ']' {
					i = j + 1
					break
				}
				if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ';' || ch == '&' || ch == ',' || ch == '}' {
					break
				}
			}
		}
		for i < len(s) {
			ch := s[i]
			if ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == ';' || ch == '&' || ch == ',' || ch == '}' || ch == ']' {
				break
			}
			i++
		}
		rawVal := s[valStart:i]
		if isRedactedPlaceholder(rawVal) {
			return i, rawVal, false
		}
		return i, "[REDACTED_AUTH_CONFIG]", true
	}
}

// looksLikeEncodedBasicCred decodes candidate standalone HTTP Basic credentials (including
// short tokens such as "YTpi" -> "a:b") and verifies printable RFC 7617 "user:password"
// structure so ordinary English prose ("Basic Authentication failed") never false-positives.
func looksLikeEncodedBasicCred(tok string) bool {
	if len(tok) < 4 {
		return false
	}
	var (
		decoded []byte
		err     error
	)
	if len(tok)%4 == 0 {
		decoded, err = base64.StdEncoding.DecodeString(tok)
	} else if !strings.ContainsRune(tok, '=') {
		decoded, err = base64.RawStdEncoding.DecodeString(tok)
	} else {
		return false
	}
	if err != nil || len(decoded) < 3 {
		return false
	}
	colon := bytes.IndexByte(decoded, ':')
	if colon < 0 || (colon == 0 && len(decoded) < 2) {
		return false
	}
	if utf8.Valid(decoded) {
		for _, r := range string(decoded) {
			if unicode.IsControl(r) {
				return false
			}
		}
		return true
	}
	// RFC 7617 also permits legacy ISO-8859-1 / Latin-1 credential bytes (0x20..0x7e and 0xa0..0xff).
	for _, b := range decoded {
		if b < 0x20 || (b >= 0x7f && b <= 0x9f) {
			return false
		}
	}
	return true
}

// isValidSSAParts enforces US SSA numbering rules matching ml/src/FtaaSService.Api/Services/DatasetService.cs:
// area != 000, 666, 900-999; group != 00; serial != 0000.
func isValidSSAParts(area, group, serial string) bool {
	if len(area) != 3 || len(group) != 2 || len(serial) != 4 {
		return false
	}
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" || serial == "0000" {
		return false
	}
	return true
}

func stripNonDigits(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func passesLuhn(digits string) bool {
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if c < '0' || c > '9' {
			return false
		}
		n := int(c - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}
