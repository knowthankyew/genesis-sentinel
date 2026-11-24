package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
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
	httpURL := fs.String("http", "", "Optional running Sentinel HTTP URL to trigger DELETE /burn (also purges configured local data_dir if different)")
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

		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if readErr != nil {
			return fmt.Errorf("read burn response: %w", readErr)
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("DELETE %s/burn returned %d: %s", target, resp.StatusCode, escapeForTerminal(strings.TrimSpace(string(body))))
		}

		var daemonRep pipeline.BurnReport
		if err := json.Unmarshal(body, &daemonRep); err != nil {
			if _, wErr := fmt.Fprintln(stdout, escapeForTerminal(string(body))); wErr != nil {
				return fmt.Errorf("write burn response: %w", wErr)
			}
			return nil
		}

		// If the daemon purged a different data_dir than our locally configured cfg.DataDir,
		// also purge cfg.DataDir so the local directory is never silently left behind.
		daemonDir := filepath.Clean(daemonRep.DataDir)
		localDir := filepath.Clean(cfg.DataDir)
		if cfg.DataDir != "" && daemonDir != localDir {
			localRep, localErr := pipeline.BurnLocalState(cfg.DataDir)
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if encErr := enc.Encode(map[string]any{
				"daemon": daemonRep,
				"local":  localRep,
			}); encErr != nil {
				return encErr
			}
			return localErr
		}

		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(daemonRep)
	}

	rep, err := pipeline.BurnLocalState(cfg.DataDir)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
