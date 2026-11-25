package security

import (
	"context"
	"crypto/subtle"
	"errors"
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
	// loopbackTransport is a reusable transport with Proxy disabled and dial-time
	// loopback IP enforcement so loopback-only clients cannot be diverted off-host via
	// environment HTTP_PROXY or hosts/DNS overrides for localhost.
	loopbackTransport = func() *http.Transport {
		if dt, ok := http.DefaultTransport.(*http.Transport); ok && dt != nil {
			cloned := dt.Clone()
			cloned.Proxy = nil
			cloned.DialContext = DialLoopbackContext
			return cloned
		}
		return &http.Transport{
			Proxy:       nil,
			DialContext: DialLoopbackContext,
		}
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

	// SanitizeURLError cause scrubbers.
	embeddedURLRe  = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)
	diagAuthCredRe = regexp.MustCompile(`(?i)\b((?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]{4,}`)
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

// DialLoopbackContext dials only validated loopback IP literals without trusting
// DNS or hosts-file resolution. For "localhost", it dials 127.0.0.1 and ::1 directly
// so a modified hosts/DNS entry cannot route a loopback-only client off-host.
func DialLoopbackContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("security: invalid dial address %q: %w", addr, err)
	}
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	if strings.EqualFold(host, "localhost") {
		switch network {
		case "tcp4", "udp4":
			return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		case "tcp6", "udp6":
			return dialer.DialContext(ctx, network, net.JoinHostPort("::1", port))
		default:
			return dialLocalhostDualStack(ctx, dialer, network, port)
		}
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("security: refusing non-loopback dial target %q", addr)
	}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

// dialLocalhostDualStack attempts 127.0.0.1 first and staggers ::1 after 150ms (or immediately
// on IPv4 error) so a stalled/filtered IPv4 loopback dial cannot consume the caller's request
// timeout before IPv6 loopback is tried.
func dialLocalhostDualStack(ctx context.Context, dialer *net.Dialer, network, port string) (net.Conn, error) {
	type dialResult struct {
		isV6 bool
		conn net.Conn
		err  error
	}

	dialCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan dialResult, 2)
	startDial := func(ip string, isV6 bool) {
		go func() {
			conn, err := dialer.DialContext(dialCtx, network, net.JoinHostPort(ip, port))
			results <- dialResult{isV6: isV6, conn: conn, err: err}
		}()
	}

	startDial("127.0.0.1", false)
	v6Started := false
	var err4, err6 error
	received := 0

	timer := time.NewTimer(150 * time.Millisecond)
	defer timer.Stop()

	for {
		if !v6Started {
			select {
			case <-ctx.Done():
				cancel()
				// Drain the lone in-flight IPv4 dial result so an established socket is never leaked.
				go func() {
					res := <-results
					if res.conn != nil {
						_ = res.conn.Close()
					}
				}()
				return nil, ctx.Err()
			case res := <-results:
				received++
				if res.err == nil {
					return res.conn, nil
				}
				err4 = res.err
				v6Started = true
				startDial("::1", true)
			case <-timer.C:
				v6Started = true
				startDial("::1", true)
			}
			continue
		}

		select {
		case <-ctx.Done():
			cancel()
			rem := 2 - received
			if rem > 0 {
				go func(pending int) {
					for i := 0; i < pending; i++ {
						res := <-results
						if res.conn != nil {
							_ = res.conn.Close()
						}
					}
				}(rem)
			}
			return nil, ctx.Err()
		case res := <-results:
			received++
			if res.err == nil {
				cancel()
				// Drain the losing goroutine asynchronously so its socket closes if it also succeeded.
				if received < 2 {
					go func() {
						loser := <-results
						if loser.conn != nil {
							_ = loser.conn.Close()
						}
					}()
				}
				return res.conn, nil
			}
			if res.isV6 {
				err6 = res.err
			} else {
				err4 = res.err
			}
			if received >= 2 {
				return nil, fmt.Errorf("security: loopback dial localhost:%s failed (ipv4: %v; ipv6: %v)", port, err4, err6)
			}
		}
	}
}

// NewLoopbackHTTPClient returns an *http.Client whose CheckRedirect policy enforces
// the loopback-only invariant on every redirect hop unless allowRemote is true.
// When allowRemote is false, environment proxies are disabled and dialing is restricted
// to loopback IP literals (with direct IPv4/IPv6 loopback dialing for localhost).
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
		client.Transport = loopbackTransport
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

type sanitizedCauseError struct {
	msg  string
	orig error
}

func (e *sanitizedCauseError) Error() string {
	return e.msg
}

func (e *sanitizedCauseError) Unwrap() error {
	return e.orig
}

func (e *sanitizedCauseError) Timeout() bool {
	var t interface{ Timeout() bool }
	return errors.As(e.orig, &t) && t.Timeout()
}

func (e *sanitizedCauseError) Temporary() bool {
	var t interface{ Temporary() bool }
	return errors.As(e.orig, &t) && t.Temporary()
}

// SanitizeURLError strips userinfo, query parameters, and fragments from wrapped *url.Error
// transport errors — including any unsanitized redirect URLs embedded inside url.Error.Err —
// while returning a *url.Error so both errors.As(err, &urlErr) and errors.Is(err, context.Canceled)
// continue to work cleanly.
func SanitizeURLError(err error) error {
	if err == nil {
		return nil
	}
	var ue *url.Error
	if !errors.As(err, &ue) || ue == nil {
		return err
	}
	cleanURL := sanitizeSingleURLString(ue.URL)
	cleanCause := "transport error"
	if ue.Err != nil {
		cleanCause = sanitizeErrMessage(ue.Err.Error())
	}
	return &url.Error{
		Op:  ue.Op,
		URL: cleanURL,
		Err: &sanitizedCauseError{
			msg:  cleanCause,
			orig: ue.Err,
		},
	}
}

func sanitizeSingleURLString(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "<redacted-url>"
	}
	u.User = nil
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return u.String()
}

func sanitizeErrMessage(msg string) string {
	lower := strings.ToLower(msg)
	// Go's net/http embeds raw Location header values (including malformed relative URLs with
	// sensitive fragments or query params) before CheckRedirect runs; replace with a safe message.
	if strings.Contains(lower, "location header") || strings.Contains(lower, "redirect") && strings.ContainsAny(msg, "?#@") {
		return "invalid or blocked redirect URL"
	}
	// If an embedded URL carries a query or fragment (where whitespace could split a query
	// value across tokens), replace the whole diagnostic safely rather than retaining fragments.
	if embeddedURLRe.MatchString(msg) && strings.ContainsAny(msg, "?#@") {
		return "sanitized HTTP transport error"
	}
	s := embeddedURLRe.ReplaceAllStringFunc(msg, func(m string) string {
		return sanitizeSingleURLString(m)
	})
	s = diagAuthCredRe.ReplaceAllString(s, "${1}[REDACTED_TOKEN]")
	if strings.ContainsAny(s, "?#@") {
		return "sanitized HTTP transport error"
	}
	return s
}
