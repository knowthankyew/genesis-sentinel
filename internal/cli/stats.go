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
	if !*allowRemote && !cfg.AllowRemoteEndpoints && !security.IsLoopbackEndpoint(target) {
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

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("query sentinel /stats at %s: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sentinel /stats returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var pretty bytes.Buffer
	if json.Indent(&pretty, body, "", "  ") == nil {
		_, _ = fmt.Fprintln(stdout, pretty.String())
		return nil
	}
	_, _ = fmt.Fprintln(stdout, string(body))
	return nil
}
