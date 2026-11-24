package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/pipeline"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
)

func runBurn(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("burn", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	yes := fs.Bool("y", false, "Confirm destructive purge of Sentinel local state")
	httpURL := fs.String("http", "", "Optional running Sentinel HTTP URL to also trigger DELETE /burn")
	authToken := fs.String("auth-token", "", "Optional Bearer token for running Sentinel HTTP API")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}

	if !*yes {
		return fmt.Errorf("refusing to purge %q without -y confirmation flag", cfg.DataDir)
	}

	// If a live Sentinel daemon URL was supplied, trigger its DELETE /burn first so in-memory state resets too.
	if *httpURL != "" {
		target := *httpURL
		if !strings.Contains(target, "://") {
			target = "http://" + target
		}
		if !cfg.AllowRemoteEndpoints && !security.IsLoopbackEndpoint(target) {
			return fmt.Errorf("refusing non-loopback burn endpoint %q", target)
		}
		req, reqErr := http.NewRequest(http.MethodDelete, strings.TrimRight(target, "/")+"/burn", nil)
		if reqErr != nil {
			return reqErr
		}
		token := *authToken
		if token == "" {
			token = cfg.AuthToken
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		// Reject redirects on DELETE /burn so a 307/308 redirect cannot bypass the endpoint policy.
		client := security.NewLoopbackHTTPClient(5*time.Second, cfg.AllowRemoteEndpoints, true)
		resp, doErr := client.Do(req)
		if doErr != nil {
			return fmt.Errorf("DELETE %s/burn failed: %w", target, doErr)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return fmt.Errorf("DELETE %s/burn returned %d: %s", target, resp.StatusCode, strings.TrimSpace(string(body)))
		}
		if _, copyErr := io.Copy(stdout, io.LimitReader(resp.Body, 1024*1024)); copyErr != nil {
			return fmt.Errorf("write burn response: %w", copyErr)
		}
		return nil
	}

	rep, err := pipeline.BurnLocalState(cfg.DataDir)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
