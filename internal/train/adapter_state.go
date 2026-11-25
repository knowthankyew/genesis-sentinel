package train

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/feedback"
	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
	"github.com/knowthankyew/genesis-sentinel/internal/triage"
)

const maxActiveAdapterBytes = 64 * 1024

// ActiveAdapterFilename persists the operator-activated LoRA adapter reference under DataDir
// and is wiped cleanly by `sentinel burn`.
const ActiveAdapterFilename = "active-adapter.json"

// ActiveAdapter records the currently activated local LoRA adapter for Tier 2 triage.
type ActiveAdapter struct {
	JobID       string    `json:"job_id,omitempty"`
	BaseModel   string    `json:"base_model"`
	AdapterPath string    `json:"adapter_path"`
	DatasetHash string    `json:"dataset_hash,omitempty"`
	ActivatedAt time.Time `json:"activated_at"`
}

// SaveActiveAdapter validates baseModel and adapterPath, then atomically writes
// active-adapter.json (0600) inside dataDir.
func SaveActiveAdapter(dataDir string, state ActiveAdapter) error {
	if strings.TrimSpace(dataDir) == "" {
		return fmt.Errorf("data_dir is empty")
	}
	if _, err := model.ValidateBaseModel(state.BaseModel); err != nil {
		return fmt.Errorf("active adapter base_model: %w", err)
	}
	cleanAdapter, err := triage.ValidateAdapterPath(state.AdapterPath)
	if err != nil {
		return err
	}
	if cleanAdapter == "" {
		return fmt.Errorf("adapter_path is required")
	}
	state.AdapterPath = cleanAdapter
	if state.ActivatedAt.IsZero() {
		state.ActivatedAt = time.Now().UTC()
	}

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("create data dir %q: %w", dataDir, err)
	}
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	tmp, err := os.CreateTemp(dataDir, ".active-adapter-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	success := false
	defer func() {
		if !success {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0600); err != nil {
		return err
	}
	if _, err := tmp.Write(payload); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, filepath.Join(dataDir, ActiveAdapterFilename)); err != nil {
		return err
	}
	success = true
	return nil
}

// LoadActiveAdapter loads and re-validates active-adapter.json from dataDir using a
// nonblocking regular-file open so a FIFO cannot block startup.
// Returns (zero, false, nil) when the file does not exist.
func LoadActiveAdapter(dataDir string) (ActiveAdapter, bool, error) {
	if strings.TrimSpace(dataDir) == "" {
		return ActiveAdapter{}, false, nil
	}
	path := filepath.Join(dataDir, ActiveAdapterFilename)
	f, fi, err := feedback.OpenRegularFileNonBlocking(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ActiveAdapter{}, false, nil
		}
		return ActiveAdapter{}, true, fmt.Errorf("open active adapter %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if fi.Size() > maxActiveAdapterBytes {
		return ActiveAdapter{}, true, fmt.Errorf("active adapter manifest %q exceeds %d-byte limit", path, maxActiveAdapterBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxActiveAdapterBytes+1))
	if err != nil {
		return ActiveAdapter{}, true, fmt.Errorf("read %q: %w", path, err)
	}
	if len(data) > maxActiveAdapterBytes {
		return ActiveAdapter{}, true, fmt.Errorf("active adapter manifest %q exceeds %d-byte limit", path, maxActiveAdapterBytes)
	}
	var state ActiveAdapter
	if err := json.Unmarshal(data, &state); err != nil {
		return ActiveAdapter{}, true, fmt.Errorf("parse %q: %w", path, err)
	}
	if _, err := model.ValidateBaseModel(state.BaseModel); err != nil {
		return ActiveAdapter{}, true, fmt.Errorf("invalid active adapter base_model in %q: %w", path, err)
	}
	cleanAdapter, err := triage.ValidateAdapterPath(state.AdapterPath)
	if err != nil {
		return ActiveAdapter{}, true, fmt.Errorf("invalid active adapter path in %q: %w", path, err)
	}
	if cleanAdapter == "" {
		return ActiveAdapter{}, true, fmt.Errorf("invalid active adapter in %q: adapter_path is required", path)
	}
	state.AdapterPath = cleanAdapter
	return state, true, nil
}

// NotifyDaemonAdapter hot-reloads the active LoRA adapter on a running `sentinel watch`
// sidecar via POST /adapter over loopback HTTP and returns the daemon's reported data_dir
// (when provided) so callers can avoid redundant unserialized local manifest writes.
func NotifyDaemonAdapter(ctx context.Context, sentinelHTTP, authToken string, state ActiveAdapter, allowRemote bool) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	target := strings.TrimSpace(sentinelHTTP)
	if target == "" {
		return "", fmt.Errorf("sentinel HTTP address is empty")
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid Sentinel HTTP URL: failed to parse host")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported Sentinel HTTP URL scheme %q (expected http or https)", u.Scheme)
	}
	if !allowRemote && !security.IsLoopbackEndpoint(target) {
		return "", fmt.Errorf("refusing non-loopback Sentinel endpoint %q without allow_remote_endpoints=true", u.Host)
	}
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.Path = strings.TrimRight(u.Path, "/")
	fullTarget := strings.TrimRight(u.String(), "/")
	redactedU := *u
	redactedU.User = nil
	redactedTarget := strings.TrimRight(redactedU.String(), "/")

	body, err := json.Marshal(map[string]string{
		"base_model":   state.BaseModel,
		"adapter_path": state.AdapterPath,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullTarget+"/adapter", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	client := security.NewLoopbackHTTPClient(5*time.Second, allowRemote, true)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s/adapter: %w", redactedTarget, security.SanitizeURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("POST %s/adapter returned HTTP %d: %s", redactedTarget, resp.StatusCode, compactErrBody(respBody, authToken))
	}
	var ack struct {
		DataDir string `json:"data_dir"`
	}
	_ = json.Unmarshal(respBody, &ack)
	return strings.TrimSpace(ack.DataDir), nil
}
