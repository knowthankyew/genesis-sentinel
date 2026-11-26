package train

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
)

const maxActiveAdapterBytes = 64 * 1024

// ActiveAdapterFilename persists the operator-activated LoRA adapter reference under DataDir
// and is wiped cleanly by `sentinel burn`.
const ActiveAdapterFilename = "active-adapter.json"

// Adapter slot identifiers supported across active-adapter.json, /adapter, and `sentinel adapter`.
const (
	SlotPrimary    = "primary"
	SlotEscalation = "escalation"
	SlotAll        = "all"
)

// Swap actions accepted by POST /adapter and `sentinel adapter`.
const (
	ActionActivate   = "activate"
	ActionRollback   = "rollback"
	ActionDeactivate = "deactivate"
)

// ErrNoRollbackAvailable is returned when rolling back a slot that has no recorded prior adapter.
var ErrNoRollbackAvailable = errors.New("no previous adapter snapshot available for rollback")

// AdapterSlot identifies a validated base model and relative LoRA adapter path pair
// persisted for the primary or escalation tier, or preserved as a rollback snapshot.
type AdapterSlot struct {
	JobID       string    `json:"job_id,omitempty"`
	BaseModel   string    `json:"base_model"`
	AdapterPath string    `json:"adapter_path"`
	DatasetHash string    `json:"dataset_hash,omitempty"`
	ActivatedAt time.Time `json:"activated_at"`
}

// ActiveAdapter records the currently activated local LoRA adapter references for Tier 2
// (primary SmolLM2 + optional Phase 5 escalation Gemma 2 2B IT) and previous rollback snapshots.
type ActiveAdapter struct {
	JobID              string       `json:"job_id,omitempty"`
	BaseModel          string       `json:"base_model,omitempty"`
	AdapterPath        string       `json:"adapter_path,omitempty"`
	DatasetHash        string       `json:"dataset_hash,omitempty"`
	ActivatedAt        time.Time    `json:"activated_at,omitempty"`
	Escalation         *AdapterSlot `json:"escalation,omitempty"`
	Previous           *AdapterSlot `json:"previous,omitempty"`
	PreviousEscalation *AdapterSlot `json:"previous_escalation,omitempty"`
}

// PrimarySlot returns the populated primary AdapterSlot when a primary adapter is active.
func (a ActiveAdapter) PrimarySlot() (AdapterSlot, bool) {
	if strings.TrimSpace(a.AdapterPath) == "" {
		return AdapterSlot{}, false
	}
	return AdapterSlot{
		JobID:       a.JobID,
		BaseModel:   a.BaseModel,
		AdapterPath: a.AdapterPath,
		DatasetHash: a.DatasetHash,
		ActivatedAt: a.ActivatedAt,
	}, true
}

// SetPrimarySlot updates the top-level primary adapter fields in place.
func (a *ActiveAdapter) SetPrimarySlot(s AdapterSlot) {
	a.JobID = s.JobID
	a.BaseModel = s.BaseModel
	a.AdapterPath = s.AdapterPath
	a.DatasetHash = s.DatasetHash
	a.ActivatedAt = s.ActivatedAt
}

// ClearPrimarySlot clears the active primary adapter fields while preserving Escalation and rollback snapshots.
func (a *ActiveAdapter) ClearPrimarySlot() {
	a.JobID = ""
	a.BaseModel = ""
	a.AdapterPath = ""
	a.DatasetHash = ""
	a.ActivatedAt = time.Time{}
}

// NormalizeSlot normalizes a slot selector into "primary", "escalation", or (when allowAll is true) "all".
func NormalizeSlot(raw string, allowAll bool) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", SlotPrimary:
		return SlotPrimary, nil
	case SlotEscalation:
		return SlotEscalation, nil
	case SlotAll:
		if allowAll {
			return SlotAll, nil
		}
		return "", fmt.Errorf("invalid adapter slot %q: must be primary or escalation", raw)
	default:
		if allowAll {
			return "", fmt.Errorf("invalid adapter slot %q: must be primary, escalation, or all", raw)
		}
		return "", fmt.Errorf("invalid adapter slot %q: must be primary or escalation", raw)
	}
}

func validateAdapterSlotStruct(slot *AdapterSlot) error {
	if slot == nil {
		return nil
	}
	slot.JobID = strings.TrimSpace(slot.JobID)
	slot.BaseModel = strings.TrimSpace(slot.BaseModel)
	slot.DatasetHash = strings.TrimSpace(slot.DatasetHash)
	if _, err := model.ValidateBaseModel(slot.BaseModel); err != nil {
		return err
	}
	cleanAdapter, err := model.ValidateAdapterPath(slot.AdapterPath)
	if err != nil {
		return err
	}
	if cleanAdapter == "" {
		return fmt.Errorf("adapter_path is required")
	}
	slot.AdapterPath = cleanAdapter
	return nil
}

func validateAndNormalizeManifest(state *ActiveAdapter) error {
	state.JobID = strings.TrimSpace(state.JobID)
	state.BaseModel = strings.TrimSpace(state.BaseModel)
	state.DatasetHash = strings.TrimSpace(state.DatasetHash)

	hasPrimaryFields := state.BaseModel != "" || strings.TrimSpace(state.AdapterPath) != ""
	if hasPrimaryFields {
		if _, err := model.ValidateBaseModel(state.BaseModel); err != nil {
			return fmt.Errorf("active adapter base_model: %w", err)
		}
		cleanAdapter, err := model.ValidateAdapterPath(state.AdapterPath)
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
	} else {
		state.ClearPrimarySlot()
	}

	if err := validateAdapterSlotStruct(state.Escalation); err != nil {
		return fmt.Errorf("escalation slot: %w", err)
	}
	if state.Escalation != nil && state.Escalation.ActivatedAt.IsZero() {
		state.Escalation.ActivatedAt = time.Now().UTC()
	}
	if err := validateAdapterSlotStruct(state.Previous); err != nil {
		return fmt.Errorf("previous primary snapshot: %w", err)
	}
	if err := validateAdapterSlotStruct(state.PreviousEscalation); err != nil {
		return fmt.Errorf("previous escalation snapshot: %w", err)
	}

	if state.AdapterPath == "" && state.Escalation == nil && state.Previous == nil && state.PreviousEscalation == nil {
		return fmt.Errorf("adapter_path is required")
	}
	return nil
}

// SaveActiveAdapter validates state and atomically writes active-adapter.json (0600) inside dataDir.
func SaveActiveAdapter(dataDir string, state ActiveAdapter) error {
	if strings.TrimSpace(dataDir) == "" {
		return fmt.Errorf("data_dir is empty")
	}
	if err := validateAndNormalizeManifest(&state); err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return fmt.Errorf("create data dir %q: %w", dataDir, err)
	}
	unlockDir, err := feedback.AcquireDirLock(dataDir)
	if err != nil {
		return fmt.Errorf("lock data dir %q: %w", dataDir, err)
	}
	defer unlockDir()
	return writeActiveAdapterUnlocked(dataDir, state)
}

func writeActiveAdapterUnlocked(dataDir string, state ActiveAdapter) error {
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if len(payload) > maxActiveAdapterBytes {
		return fmt.Errorf("active adapter manifest (%d bytes) exceeds %d-byte limit", len(payload), maxActiveAdapterBytes)
	}

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

func readAndValidateManifest(dataDir string) (ActiveAdapter, bool, error) {
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
	if err := validateAndNormalizeManifest(&state); err != nil {
		return ActiveAdapter{}, true, fmt.Errorf("invalid active adapter in %q: %w", path, err)
	}
	return state, true, nil
}

// LoadActiveAdapter loads and re-validates active-adapter.json from dataDir using a
// nonblocking regular-file open so a FIFO cannot block startup.
// Returns (zero, false, nil) when the file does not exist.
func LoadActiveAdapter(dataDir string) (ActiveAdapter, bool, error) {
	return readAndValidateManifest(dataDir)
}

func mutateActiveAdapterUnlocked(dataDir string, fn func(*ActiveAdapter) (remove bool, err error)) (ActiveAdapter, error) {
	if strings.TrimSpace(dataDir) == "" {
		return ActiveAdapter{}, fmt.Errorf("data_dir is empty")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return ActiveAdapter{}, fmt.Errorf("create data dir %q: %w", dataDir, err)
	}
	unlockDir, err := feedback.AcquireDirLock(dataDir)
	if err != nil {
		return ActiveAdapter{}, fmt.Errorf("lock data dir %q: %w", dataDir, err)
	}
	defer unlockDir()

	cur, exists, err := readAndValidateManifest(dataDir)
	if err != nil && exists {
		return ActiveAdapter{}, err
	}
	remove, err := fn(&cur)
	if err != nil {
		return ActiveAdapter{}, err
	}
	if remove {
		err := os.Remove(filepath.Join(dataDir, ActiveAdapterFilename))
		if err != nil && !os.IsNotExist(err) {
			return ActiveAdapter{}, err
		}
		return ActiveAdapter{}, nil
	}
	if err := validateAndNormalizeManifest(&cur); err != nil {
		return ActiveAdapter{}, err
	}
	if err := writeActiveAdapterUnlocked(dataDir, cur); err != nil {
		return ActiveAdapter{}, err
	}
	return cur, nil
}

// UpdateActiveAdapterSlot atomically updates either the primary or escalation slot in
// active-adapter.json, preserving the sibling slot and recording the displaced adapter
// for one-command rollback.
func UpdateActiveAdapterSlot(dataDir, slot string, next AdapterSlot) (ActiveAdapter, error) {
	normSlot, err := NormalizeSlot(slot, false)
	if err != nil {
		return ActiveAdapter{}, err
	}
	if err := validateAdapterSlotStruct(&next); err != nil {
		return ActiveAdapter{}, err
	}
	if next.ActivatedAt.IsZero() {
		next.ActivatedAt = time.Now().UTC()
	}
	return mutateActiveAdapterUnlocked(dataDir, func(cur *ActiveAdapter) (bool, error) {
		switch normSlot {
		case SlotPrimary:
			if prev, ok := cur.PrimarySlot(); ok && (prev.AdapterPath != next.AdapterPath || prev.BaseModel != next.BaseModel || prev.JobID != next.JobID) {
				prevCopy := prev
				cur.Previous = &prevCopy
			}
			cur.SetPrimarySlot(next)
		case SlotEscalation:
			if cur.Escalation != nil && (cur.Escalation.AdapterPath != next.AdapterPath || cur.Escalation.BaseModel != next.BaseModel || cur.Escalation.JobID != next.JobID) {
				prevCopy := *cur.Escalation
				cur.PreviousEscalation = &prevCopy
			}
			nextCopy := next
			cur.Escalation = &nextCopy
		}
		return false, nil
	})
}

// RollbackActiveAdapterSlot atomically restores the prior adapter for slot ("primary" or
// "escalation") and swaps the replaced adapter into the rollback snapshot so rollbacks
// are safely reversible.
func RollbackActiveAdapterSlot(dataDir, slot string) (ActiveAdapter, AdapterSlot, error) {
	normSlot, err := NormalizeSlot(slot, false)
	if err != nil {
		return ActiveAdapter{}, AdapterSlot{}, err
	}
	var restored AdapterSlot
	updated, err := mutateActiveAdapterUnlocked(dataDir, func(cur *ActiveAdapter) (bool, error) {
		switch normSlot {
		case SlotPrimary:
			if cur.Previous == nil {
				return false, ErrNoRollbackAvailable
			}
			restored = *cur.Previous
			if curPrimary, ok := cur.PrimarySlot(); ok {
				prevCopy := curPrimary
				cur.Previous = &prevCopy
			} else {
				cur.Previous = nil
			}
			cur.SetPrimarySlot(restored)
		case SlotEscalation:
			if cur.PreviousEscalation == nil {
				return false, ErrNoRollbackAvailable
			}
			restored = *cur.PreviousEscalation
			if cur.Escalation != nil {
				prevCopy := *cur.Escalation
				cur.PreviousEscalation = &prevCopy
			} else {
				cur.PreviousEscalation = nil
			}
			restoredCopy := restored
			cur.Escalation = &restoredCopy
		}
		return false, nil
	})
	return updated, restored, err
}

// DeactivateActiveAdapterSlot clears the active adapter for slot ("primary", "escalation", or
// "all") while retaining its rollback snapshot (unless nothing remains active or snapshotted,
// in which case active-adapter.json is removed).
func DeactivateActiveAdapterSlot(dataDir, slot string) (ActiveAdapter, bool, error) {
	normSlot, err := NormalizeSlot(slot, true)
	if err != nil {
		return ActiveAdapter{}, false, err
	}
	if _, exists, err := readAndValidateManifest(dataDir); err != nil && !exists {
		return ActiveAdapter{}, false, err
	} else if !exists {
		return ActiveAdapter{}, false, nil
	}
	changed := false
	updated, err := mutateActiveAdapterUnlocked(dataDir, func(cur *ActiveAdapter) (bool, error) {
		if normSlot == SlotPrimary || normSlot == SlotAll {
			if prev, ok := cur.PrimarySlot(); ok {
				prevCopy := prev
				cur.Previous = &prevCopy
				cur.ClearPrimarySlot()
				changed = true
			}
		}
		if normSlot == SlotEscalation || normSlot == SlotAll {
			if cur.Escalation != nil {
				prevCopy := *cur.Escalation
				cur.PreviousEscalation = &prevCopy
				cur.Escalation = nil
				changed = true
			}
		}
		remove := cur.AdapterPath == "" && cur.Escalation == nil && cur.Previous == nil && cur.PreviousEscalation == nil
		return remove, nil
	})
	return updated, changed, err
}

// AdapterSwapRequest configures a live adapter operation via POST /adapter.
type AdapterSwapRequest struct {
	Slot        string `json:"slot,omitempty"`   // "primary" (default) | "escalation"
	Action      string `json:"action,omitempty"` // "activate" (default) | "rollback" | "deactivate"
	JobID       string `json:"job_id,omitempty"`
	BaseModel   string `json:"base_model,omitempty"`
	AdapterPath string `json:"adapter_path,omitempty"`
	DatasetHash string `json:"dataset_hash,omitempty"`
	Verify      bool   `json:"verify,omitempty"` // preflight /healthz check before live commit
	Enable      bool   `json:"enable,omitempty"` // dynamically enable slot inference client if off
}

// AdapterSwapRecord records a single hot-swap, rollback, or deactivation audit event.
type AdapterSwapRecord struct {
	Slot                string    `json:"slot"`
	Action              string    `json:"action"`
	BaseModel           string    `json:"base_model,omitempty"`
	AdapterPath         string    `json:"adapter_path,omitempty"`
	JobID               string    `json:"job_id,omitempty"`
	PreviousBaseModel   string    `json:"previous_base_model,omitempty"`
	PreviousAdapterPath string    `json:"previous_adapter_path,omitempty"`
	Verified            bool      `json:"verified"`
	SwappedAt           time.Time `json:"swapped_at"`
}

// SlotStatus summarizes the live runtime + rollback posture of a single inference slot.
type SlotStatus struct {
	Slot                string    `json:"slot"`
	Mode                string    `json:"mode"`
	Enabled             bool      `json:"enabled"`
	BaseModel           string    `json:"base_model,omitempty"`
	AdapterPath         string    `json:"adapter_path,omitempty"`
	JobID               string    `json:"job_id,omitempty"`
	DatasetHash         string    `json:"dataset_hash,omitempty"`
	InferenceURL        string    `json:"inference_url,omitempty"`
	SwappedAt           time.Time `json:"swapped_at,omitempty"`
	HasRollback         bool      `json:"has_rollback"`
	PreviousBaseModel   string    `json:"previous_base_model,omitempty"`
	PreviousAdapterPath string    `json:"previous_adapter_path,omitempty"`
}

// AdapterStatusResponse is returned by GET / POST / DELETE /adapter on `sentinel watch`.
type AdapterStatusResponse struct {
	Status            string              `json:"status"`
	Slot              string              `json:"slot,omitempty"`
	Action            string              `json:"action,omitempty"`
	JobID             string              `json:"job_id,omitempty"`
	BaseModel         string              `json:"base_model,omitempty"`
	AdapterPath       string              `json:"adapter_path,omitempty"`
	DataDir           string              `json:"data_dir,omitempty"`
	TriageEnabled     bool                `json:"triage_enabled"`
	EscalationEnabled bool                `json:"escalation_enabled"`
	Verified          bool                `json:"verified,omitempty"`
	HealthStatus      string              `json:"health_status,omitempty"`
	HealthBaseModel   string              `json:"health_base_model,omitempty"`
	HealthBackend     string              `json:"health_backend,omitempty"`
	Primary           *SlotStatus         `json:"primary,omitempty"`
	Escalation        *SlotStatus         `json:"escalation,omitempty"`
	AdapterSwapsTotal uint64              `json:"adapter_swaps_total"`
	RecentSwaps       []AdapterSwapRecord `json:"recent_swaps,omitempty"`
}

func parseDaemonBaseURL(sentinelHTTP string, allowRemote bool) (fullTarget, redactedTarget string, err error) {
	target := strings.TrimSpace(sentinelHTTP)
	if target == "" {
		return "", "", fmt.Errorf("sentinel HTTP address is empty")
	}
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("invalid Sentinel HTTP URL: failed to parse host")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", fmt.Errorf("unsupported Sentinel HTTP URL scheme %q (expected http or https)", u.Scheme)
	}
	if !allowRemote && !security.IsLoopbackEndpoint(target) {
		return "", "", fmt.Errorf("refusing non-loopback Sentinel endpoint %q without allow_remote_endpoints=true", u.Host)
	}
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.Path = strings.TrimRight(u.Path, "/")
	fullTarget = strings.TrimRight(u.String(), "/")
	redactedU := *u
	redactedU.User = nil
	redactedTarget = strings.TrimRight(redactedU.String(), "/")
	return fullTarget, redactedTarget, nil
}

func doDaemonAdapterRequest(ctx context.Context, method, sentinelHTTP, authToken, query string, reqBody any, allowRemote bool) (AdapterStatusResponse, string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	fullTarget, redactedTarget, err := parseDaemonBaseURL(sentinelHTTP, allowRemote)
	if err != nil {
		return AdapterStatusResponse{}, "", err
	}
	var bodyReader io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return AdapterStatusResponse{}, redactedTarget, err
		}
		bodyReader = bytes.NewReader(raw)
	}
	reqURL := fullTarget + "/adapter"
	if query != "" {
		reqURL += "?" + query
	}
	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return AdapterStatusResponse{}, redactedTarget, err
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	client := security.NewLoopbackHTTPClient(10*time.Second, allowRemote, true)
	resp, err := client.Do(req)
	if err != nil {
		return AdapterStatusResponse{}, redactedTarget, fmt.Errorf("%s %s/adapter: %w", method, redactedTarget, security.SanitizeURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxActiveAdapterBytes+1))
	if readErr != nil {
		return AdapterStatusResponse{}, redactedTarget, fmt.Errorf("%s %s/adapter response could not be confirmed: %w", method, redactedTarget, readErr)
	}
	if len(respBody) > maxActiveAdapterBytes {
		return AdapterStatusResponse{}, redactedTarget, fmt.Errorf("%s %s/adapter response exceeded %d-byte limit", method, redactedTarget, maxActiveAdapterBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return AdapterStatusResponse{}, redactedTarget, fmt.Errorf("%s %s/adapter returned HTTP %d: %s", method, redactedTarget, resp.StatusCode, compactErrBody(respBody, authToken))
	}
	var out AdapterStatusResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return AdapterStatusResponse{}, redactedTarget, fmt.Errorf("%s %s/adapter returned invalid JSON response", method, redactedTarget)
	}
	return out, redactedTarget, nil
}

// QueryDaemonAdapterStatus fetches live primary + escalation adapter status from `GET /adapter`.
func QueryDaemonAdapterStatus(ctx context.Context, sentinelHTTP, authToken string, allowRemote bool) (AdapterStatusResponse, error) {
	out, _, err := doDaemonAdapterRequest(ctx, http.MethodGet, sentinelHTTP, authToken, "", nil, allowRemote)
	return out, err
}

// DaemonAdapterAction executes a live adapter swap, rollback, or deactivation via `POST /adapter`.
func DaemonAdapterAction(ctx context.Context, sentinelHTTP, authToken string, req AdapterSwapRequest, allowRemote bool) (AdapterStatusResponse, error) {
	out, redactedTarget, err := doDaemonAdapterRequest(ctx, http.MethodPost, sentinelHTTP, authToken, "", req, allowRemote)
	if err != nil {
		return AdapterStatusResponse{}, err
	}
	switch strings.TrimSpace(out.Status) {
	case "activated", "rolled_back", "deactivated":
		return out, nil
	default:
		return AdapterStatusResponse{}, fmt.Errorf("POST %s/adapter returned unexpected status %q", redactedTarget, out.Status)
	}
}

// DeactivateDaemonAdapter deactivates the active adapter for slot ("primary", "escalation", or "all")
// via `DELETE /adapter`.
func DeactivateDaemonAdapter(ctx context.Context, sentinelHTTP, authToken, slot string, allowRemote bool) (AdapterStatusResponse, error) {
	normSlot, err := NormalizeSlot(slot, true)
	if err != nil {
		return AdapterStatusResponse{}, err
	}
	out, _, err := doDaemonAdapterRequest(ctx, http.MethodDelete, sentinelHTTP, authToken, "slot="+url.QueryEscape(normSlot), nil, allowRemote)
	return out, err
}

// NotifyDaemonAdapter hot-reloads the active LoRA adapter on a running `sentinel watch`
// sidecar via POST /adapter over loopback HTTP and returns the daemon's reported data_dir
// (when provided) so callers can avoid redundant unserialized local manifest writes.
func NotifyDaemonAdapter(ctx context.Context, sentinelHTTP, authToken string, state ActiveAdapter, allowRemote bool) (string, error) {
	out, redactedTarget, err := doDaemonAdapterRequest(ctx, http.MethodPost, sentinelHTTP, authToken, "", AdapterSwapRequest{
		JobID:       strings.TrimSpace(state.JobID),
		BaseModel:   state.BaseModel,
		AdapterPath: state.AdapterPath,
		DatasetHash: strings.TrimSpace(state.DatasetHash),
	}, allowRemote)
	if err != nil {
		return "", err
	}
	if out.Status != "activated" {
		return "", fmt.Errorf("POST %s/adapter returned incomplete or invalid activation acknowledgement (daemon may already have applied the adapter)", redactedTarget)
	}
	return out.DataDir, nil
}
