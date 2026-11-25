package feedback

import (
	"regexp"
	"strings"

	"github.com/knowthankyew/genesis-sentinel/internal/security"
)

var (
	// PEM private key blocks (single-line or multi-line).
	pemPrivateKeyRe = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

	// JWT tokens (3 base64url segments beginning with eyJ).
	jwtRe = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)

	// Authorization Bearer and Basic credentials (both plain headers and JSON-quoted header keys).
	authHeaderCredRe = regexp.MustCompile(`(?i)(["']?)\b((?:Proxy-)?Authorization)(["']?\s*[:=]\s*["']?(?:Bearer|Basic)\s+)([A-Za-z0-9._~+/=-]{4,})`)
	bearerRe         = regexp.MustCompile(`(?i)\b(Bearer\s+)([A-Za-z0-9._~+/=-]{8,})`)
	basicTokenRe     = regexp.MustCompile(`(?i)\b(Basic\s+)([A-Za-z0-9+/]{8,}={0,2})`)

	// Credential-bearing *_AUTH_CONFIG keys (e.g., DOCKER_AUTH_CONFIG JSON objects or strings).
	authConfigKeyRe = regexp.MustCompile(`(?i)(["']?)\b([A-Z0-9_-]*auth[_-]?config)(["']?\s*[=:]\s*)`)

	// Common cloud, VCS, and AI API key prefixes.
	apiKeyPrefixRe = regexp.MustCompile(`\b(?:(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b`)

	// Credential key=value or key: value assignments (both unquoted and JSON-quoted keys,
	// escape-aware for quoted strings containing \" or \', never matching redacted placeholders).
	credKVRe = regexp.MustCompile(`(?i)(["']?)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)(["']?\s*[=:]\s*)("(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s,;&}\]]+)`)

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
	if jwtRe.MatchString(s) {
		s = jwtRe.ReplaceAllString(s, "[REDACTED_JWT]")
		addFinding("jwt")
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
	s = credKVRe.ReplaceAllStringFunc(s, func(match string) string {
		sub := credKVRe.FindStringSubmatch(match)
		if len(sub) < 5 {
			return match
		}
		rawVal := sub[4]
		val := strings.Trim(rawVal, `"'`)
		if isRedactedPlaceholder(val) {
			return match
		}
		addFinding("credential_value")
		if len(rawVal) >= 2 && rawVal[0] == '"' && rawVal[len(rawVal)-1] == '"' {
			return sub[1] + sub[2] + sub[3] + `"[REDACTED_SECRET]"`
		}
		if len(rawVal) >= 2 && rawVal[0] == '\'' && rawVal[len(rawVal)-1] == '\'' {
			return sub[1] + sub[2] + sub[3] + `'[REDACTED_SECRET]'`
		}
		return sub[1] + sub[2] + sub[3] + "[REDACTED_SECRET]"
	})
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
	s = cardCandidateRe.ReplaceAllStringFunc(s, func(match string) string {
		digits := stripNonDigits(match)
		if len(digits) >= 13 && len(digits) <= 19 && passesLuhn(digits) {
			addFinding("payment_card")
			return "[REDACTED_CARD]"
		}
		return match
	})

	return s, findings
}

// ScanForPII performs a fail-closed pre-export compliance scan mirroring FTaaS's
// DatasetService.ScanForPii (SSA-valid SSNs and Luhn-valid payment cards) plus high-risk
// unredacted secret/PII patterns (PEM private keys, JWTs, Bearer/Basic authorization
// credentials, *_AUTH_CONFIG secrets, credential KV assignments, emails, and cloud/VCS API keys).
func ScanForPII(text string) (string, bool) {
	if strings.TrimSpace(text) == "" {
		return "", false
	}
	if pemPrivateKeyRe.MatchString(text) {
		return "PEM Private Key", true
	}
	if jwtRe.MatchString(text) {
		return "JWT Bearer Token", true
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
	for _, match := range cardCandidateRe.FindAllString(text, -1) {
		digits := stripNonDigits(match)
		if len(digits) >= 13 && len(digits) <= 19 && passesLuhn(digits) {
			return "Credit/Debit Card Number", true
		}
	}
	return "", false
}

func isRedactedPlaceholder(val string) bool {
	return val == "" || strings.HasPrefix(val, "[REDACTED") || val == "<STR>" || val == "<HEX>" || val == "<NUM>"
}

func hasUnredactedCredKV(text string) bool {
	for _, sub := range credKVRe.FindAllStringSubmatch(text, -1) {
		if len(sub) < 5 {
			continue
		}
		val := strings.Trim(sub[4], `"'`)
		if !isRedactedPlaceholder(val) {
			return true
		}
	}
	return false
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
			if ch == '\r' || ch == '\n' {
				break
			}
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
		return i, "[REDACTED_AUTH_CONFIG]", true
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

// looksLikeEncodedBasicCred distinguishes standalone Base64 Basic credentials (mixed case,
// digits, base64 punctuation, or '=' padding) from ordinary English prose such as "Basic authentication".
func looksLikeEncodedBasicCred(tok string) bool {
	if len(tok) < 8 {
		return false
	}
	var hasLower, hasUpper, hasDigit, hasB64Sym bool
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '+' || c == '/' || c == '=':
			hasB64Sym = true
		}
	}
	return hasB64Sym || hasDigit || (hasLower && hasUpper)
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
