package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
)

const (
	maxStatsResponseBytes  = 1024 * 1024     // 1 MiB raw HTTP body limit
	maxFormattedStatsBytes = 2 * 1024 * 1024 // 2 MiB upper bound on pretty-printed JSON expansion
)

func runStats(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("stats", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	httpURL := fs.String("http", "", "Sentinel HTTP base URL (default: http://<config.http>)")
	authToken := fs.String("auth-token", "", "Optional Bearer token for Sentinel HTTP API")
	allowRemote := fs.Bool("allow-remote", false, "Allow querying a non-loopback Sentinel endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}

	target := *httpURL
	if target == "" {
		target = "http://" + cfg.HTTPAddr
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	remoteAllowed := *allowRemote || cfg.AllowRemoteEndpoints
	if !remoteAllowed && !security.IsLoopbackEndpoint(target) {
		return fmt.Errorf("refusing non-loopback stats endpoint %q without --allow-remote", target)
	}

	token := *authToken
	if token == "" {
		token = cfg.AuthToken
	}

	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(target, "/")+"/stats", nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := security.NewLoopbackHTTPClient(5*time.Second, remoteAllowed, false)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("query sentinel /stats at %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxStatsResponseBytes+1))
	if err != nil {
		return err
	}
	if len(body) > maxStatsResponseBytes {
		return fmt.Errorf("sentinel /stats response exceeded %d-byte limit", maxStatsResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sentinel /stats returned %d: %s", resp.StatusCode, escapeForTerminal(strings.TrimSpace(string(body))))
	}

	if json.Valid(body) {
		// Compact first and only pretty-print when nesting depth stays within safe expansion budget,
		// preventing deeply nested compact JSON from expanding into gigabytes in memory.
		var compact bytes.Buffer
		if err := json.Compact(&compact, body); err == nil {
			if formatted, ok := boundedIndentJSON(compact.Bytes(), maxFormattedStatsBytes); ok {
				if _, err := fmt.Fprintln(stdout, string(formatted)); err != nil {
					return fmt.Errorf("write stats output: %w", err)
				}
				return nil
			}
			if _, err := fmt.Fprintln(stdout, compact.String()); err != nil {
				return fmt.Errorf("write stats output: %w", err)
			}
			return nil
		}
	}

	// Non-JSON 200 response: escape control bytes so raw terminal escape sequences cannot alter display.
	if _, err := fmt.Fprintln(stdout, escapeForTerminal(string(body))); err != nil {
		return fmt.Errorf("write stats output: %w", err)
	}
	return nil
}

// boundedIndentJSON pretty-prints valid compact JSON only if the resulting output
// stays within maxBytes. Avoids gigabyte expansion on deeply nested adversarial arrays.
func boundedIndentJSON(compact []byte, maxBytes int) ([]byte, bool) {
	// Quick nesting-depth check: each nesting level adds 2 spaces per element.
	// Estimate worst-case expanded size without allocating a giant buffer.
	depth := 0
	maxDepth := 0
	inStr := false
	escaped := false
	estBytes := len(compact)
	for _, b := range compact {
		if inStr {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				inStr = false
			}
			continue
		}
		switch b {
		case '"':
			inStr = true
		case '{', '[':
			depth++
			if depth > maxDepth {
				maxDepth = depth
			}
			estBytes += 1 + depth*2
		case '}', ']':
			if depth > 0 {
				depth--
			}
			estBytes += 1 + depth*2
		case ',':
			estBytes += 1 + depth*2
		case ':':
			estBytes++
		}
		if estBytes > maxBytes {
			return nil, false
		}
	}

	var pretty bytes.Buffer
	pretty.Grow(estBytes)
	if err := json.Indent(&pretty, compact, "", "  "); err != nil {
		return nil, false
	}
	if pretty.Len() > maxBytes {
		return nil, false
	}
	return pretty.Bytes(), true
}

// escapeForTerminal escapes non-printable ASCII/Unicode control characters in untrusted
// diagnostic strings so responses cannot inject terminal escape sequences.
func escapeForTerminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\t' {
			b.WriteRune(r)
			continue
		}
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			quoted := strconv.QuoteRuneToASCII(r)
			b.WriteString(quoted[1 : len(quoted)-1])
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
