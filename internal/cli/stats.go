package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
)

const maxStatsResponseBytes = 1024 * 1024 // 1 MiB

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
		return fmt.Errorf("sentinel /stats returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var pretty bytes.Buffer
	if json.Indent(&pretty, body, "", "  ") == nil {
		if _, err := fmt.Fprintln(stdout, pretty.String()); err != nil {
			return fmt.Errorf("write stats output: %w", err)
		}
		return nil
	}
	if _, err := fmt.Fprintln(stdout, string(body)); err != nil {
		return fmt.Errorf("write stats output: %w", err)
	}
	return nil
}
