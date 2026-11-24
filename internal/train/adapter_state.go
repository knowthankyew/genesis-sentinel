package train

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
	"github.com/knowthankyew/genesis-sentinel/internal/triage"
)

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

// LoadActiveAdapter loads and re-validates active-adapter.json from dataDir.
// Returns (zero, false, nil) when the file does not exist.
func LoadActiveAdapter(dataDir string) (ActiveAdapter, bool, error) {
	if strings.TrimSpace(dataDir) == "" {
		return ActiveAdapter{}, false, nil
	}
	path := filepath.Join(dataDir, ActiveAdapterFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ActiveAdapter{}, false, nil
		}
		return ActiveAdapter{}, false, err
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
	state.AdapterPath = cleanAdapter
	return state, true, nil
}

// NotifyDaemonAdapter hot-reloads the active LoRA adapter on a running `sentinel watch`
// sidecar via POST /adapter over loopback HTTP.
func NotifyDaemonAdapter(ctx context.Context, sentinelHTTP, authToken string, state ActiveAdapter, allowRemote bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	target := strings.TrimSpace(sentinelHTTP)
	if target == "" {
		return fmt.Errorf("sentinel HTTP address is empty")
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	if !allowRemote && !security.IsLoopbackEndpoint(target) {
		return fmt.Errorf("refusing non-loopback Sentinel endpoint %q without allow_remote_endpoints=true", target)
	}
	body, err := json.Marshal(map[string]string{
		"base_model":   state.BaseModel,
		"adapter_path": state.AdapterPath,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(target, "/")+"/adapter", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	client := security.NewLoopbackHTTPClient(5*time.Second, allowRemote, true)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s/adapter: %w", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("POST %s/adapter returned HTTP %d: %s", target, resp.StatusCode, compactErrBody(respBody))
	}
	return nil
}
