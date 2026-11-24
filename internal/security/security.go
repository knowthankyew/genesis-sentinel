package security

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

var (
	// noProxyTransport is a reusable transport with Proxy disabled so loopback-only
	// clients cannot be diverted to an environment HTTP_PROXY via mixed-case LOCALHOST URLs.
	noProxyTransport = func() *http.Transport {
		if dt, ok := http.DefaultTransport.(*http.Transport); ok && dt != nil {
			cloned := dt.Clone()
			cloned.Proxy = nil
			return cloned
		}
		return &http.Transport{Proxy: nil}
	}()

	// specialTokenPattern matches common LLM chat-template and control token delimiters
	// such as <|im_start|>, <|im_end|>, <|eot_id|>, and <|endoftext|>.
	specialTokenPattern = regexp.MustCompile(`<\|[^|>]{1,64}\|>`)

	// gemmaTurnPattern matches Gemma conversation turn delimiters.
	gemmaTurnPattern = regexp.MustCompile(`<(?:start_of_turn|end_of_turn)>`)

	// injectionHeuristics detect common plain-text prompt injection cues inside untrusted log payloads.
	// Matches are surfaced as TriageVerdict metadata so analysts never mistake injected text for trusted signals.
	injectionHeuristics = []struct {
		name string
		re   *regexp.Regexp
	}{
		{name: "ignore_previous", re: regexp.MustCompile(`(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?)\b`)},
		{name: "force_benign_verdict", re: regexp.MustCompile(`(?i)\b(classify|mark|label|treat|output)\s+(this|as)\s+.*\[?benign\]?\b`)},
		{name: "role_override", re: regexp.MustCompile(`(?i)\b(you\s+are\s+now|act\s+as\s+a|new\s+system\s+prompt)\b`)},
	}
)

// AuthMiddleware enforces Bearer token authentication using constant-time comparison
// when expectedToken is non-empty, mirroring Genesis's HTTP security posture.
func AuthMiddleware(expectedToken string, next http.Handler) http.Handler {
	if expectedToken == "" {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		var token string
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			token = strings.TrimSpace(authHeader[7:])
		}
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="Genesis-Sentinel"`)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"unauthorized: invalid or missing bearer token"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// IsBindingAllInterfaces returns true if a listen address binds to wildcard interfaces.
func IsBindingAllInterfaces(addr string) bool {
	trimmed := strings.TrimSpace(addr)
	return strings.HasPrefix(trimmed, ":") ||
		strings.HasPrefix(trimmed, "0.0.0.0:") ||
		strings.HasPrefix(trimmed, "[::]:") ||
		trimmed == "0.0.0.0" ||
		trimmed == "::"
}

// IsLoopbackEndpoint reports whether a host:port or http(s):// URL resolves strictly
// to a local loopback address (127.0.0.0/8, ::1, or localhost).
func IsLoopbackEndpoint(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return false
	}

	var host string
	if strings.Contains(trimmed, "://") {
		u, err := url.Parse(trimmed)
		if err != nil || u.Host == "" {
			return false
		}
		host = u.Hostname()
	} else {
		h, _, err := net.SplitHostPort(trimmed)
		if err != nil {
			host = strings.Trim(trimmed, "[]")
		} else {
			host = h
		}
	}

	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// NewLoopbackHTTPClient returns an *http.Client whose CheckRedirect policy enforces
// the loopback-only invariant on every redirect hop unless allowRemote is true.
// When allowRemote is false, environment proxies are also disabled on the transport
// so mixed-case localhost URLs cannot trigger Go's case-sensitive localhost proxy bypass.
// When blockRedirects is true, all HTTP redirects are rejected outright (e.g., for DELETE /burn).
func NewLoopbackHTTPClient(timeout time.Duration, allowRemote, blockRedirects bool) *http.Client {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if blockRedirects {
				return fmt.Errorf("redirect to %q blocked by security policy", req.URL.String())
			}
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if !allowRemote && !IsLoopbackEndpoint(req.URL.String()) {
				return fmt.Errorf("redirect to non-loopback endpoint %q blocked by loopback policy", req.URL.String())
			}
			return nil
		},
	}
	if !allowRemote {
		client.Transport = noProxyTransport
	}
	return client
}

// SanitizeUntrustedLogText neutralizes chat-template delimiters and unsafe control bytes
// in untrusted log payloads before they are embedded in Tier 2 triage prompts.
// It also returns any detected prompt-injection heuristic signal names.
func SanitizeUntrustedLogText(raw string, maxBytes int) (string, []string) {
	if maxBytes <= 0 {
		maxBytes = 2048
	}

	// Detect adversarial injection patterns before rewriting delimiters.
	var signals []string
	if specialTokenPattern.MatchString(raw) || gemmaTurnPattern.MatchString(raw) {
		signals = append(signals, "template_delimiter_escape")
	}
	for _, h := range injectionHeuristics {
		if h.re.MatchString(raw) {
			signals = append(signals, h.name)
		}
	}

	// Neutralize model control tokens so hostile log payloads cannot forge assistant turns.
	cleaned := specialTokenPattern.ReplaceAllStringFunc(raw, func(tok string) string {
		inner := tok[2 : len(tok)-2]
		return "[" + inner + "]"
	})
	cleaned = gemmaTurnPattern.ReplaceAllStringFunc(cleaned, func(tok string) string {
		inner := tok[1 : len(tok)-1]
		return "[" + inner + "]"
	})
	cleaned = strings.ReplaceAll(cleaned, "<s>", "[s]")
	cleaned = strings.ReplaceAll(cleaned, "</s>", "[/s]")

	// Strip non-printable ASCII control characters except horizontal tab and newline.
	var b strings.Builder
	b.Grow(min(len(cleaned), maxBytes))
	for _, r := range cleaned {
		if r == '\r' {
			continue
		}
		if r < 0x20 && r != '\n' && r != '\t' {
			continue
		}
		if r == 0x7f {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxBytes {
			break
		}
		b.WriteRune(r)
	}

	return b.String(), signals
}
