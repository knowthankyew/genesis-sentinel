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

	// Authorization Bearer tokens.
	bearerRe = regexp.MustCompile(`(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}`)

	// Common cloud, VCS, and AI API key prefixes.
	apiKeyPrefixRe = regexp.MustCompile(`\b(?:(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b`)

	// Credential key=value or key: value assignments (never matching already-redacted placeholders).
	credKVRe = regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)(\s*[=:]\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&]+)`)

	// Email addresses.
	emailRe = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)

	// Delimited SSN candidates (validated against SSA area/group/serial rules in Go code
	// because Go RE2 intentionally omits negative lookahead).
	ssnDelimitedCandidateRe = regexp.MustCompile(`\b(\d{3})([- ])(\d{2})([- ])(\d{4})\b`)

	// Contextual SSN candidates preceded by "ssn" or "social security".
	ssnContextualCandidateRe = regexp.MustCompile(`(?i)\b(ssn|social\s*security(?:\s*number)?)([^\d]{1,10})(\d{3})([- ]?)(\d{2})([- ]?)(\d{4})\b`)

	// Credit/debit card digit candidates (13-19 digits, formatted or contiguous; validated via Luhn).
	cardCandidateRe = regexp.MustCompile(`\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{13,19}\b`)
)

// RedactText neutralizes chat-template delimiters and scrubs PII/secrets (PEM private keys,
// JWTs, Bearer tokens, cloud/VCS API keys, credential key=value pairs, emails, SSA-valid SSNs,
// and Luhn-valid payment cards) before any log text enters an FTaaS JSONL dataset.
// Returns the scrubbed string and deduplicated list of redacted categories.
func RedactText(raw string) (string, []string) {
	if raw == "" {
		return "", nil
	}

	// Neutralize chat-template tokens without truncating valid long prompts (length caps
	// are enforced separately by the dataset store and FTaaS ceilings).
	s, _ := security.SanitizeUntrustedLogText(raw, len(raw)+64)

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
	if bearerRe.MatchString(s) {
		s = bearerRe.ReplaceAllString(s, "${1}[REDACTED_TOKEN]")
		addFinding("bearer_token")
	}
	if apiKeyPrefixRe.MatchString(s) {
		s = apiKeyPrefixRe.ReplaceAllString(s, "[REDACTED_API_KEY]")
		addFinding("api_key")
	}
	s = credKVRe.ReplaceAllStringFunc(s, func(match string) string {
		sub := credKVRe.FindStringSubmatch(match)
		if len(sub) < 4 {
			return match
		}
		val := strings.Trim(sub[3], `"'`)
		if strings.HasPrefix(val, "[REDACTED") || val == "<STR>" || val == "<HEX>" || val == "<NUM>" {
			return match
		}
		addFinding("credential_value")
		return sub[1] + sub[2] + "[REDACTED_SECRET]"
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
// unredacted secret patterns (PEM private keys, JWTs, cloud/VCS API key prefixes).
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
	if apiKeyPrefixRe.MatchString(text) {
		return "API Access Key", true
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
