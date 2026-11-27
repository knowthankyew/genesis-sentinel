package train

import (
	"bytes"
	"context"
	"crypto/sha256"
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

// MaxAdapterResponseBytes bounds HTTP /adapter status responses returned to the CLI client.
const MaxAdapterResponseBytes = maxActiveAdapterBytes

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

// ErrRollbackTargetChanged is returned when the persisted rollback snapshot changes
// between preflight verification and rollback commit.
var ErrRollbackTargetChanged = errors.New("rollback target changed while preflight verification was pending")

// AdapterSlot identifies a validated base model and relative LoRA adapter path pair
// persisted for the primary or escalation tier, or preserved as a rollback snapshot.
type AdapterSlot struct {
	JobID       string    `json:"job_id,omitempty"`
	BaseModel   string    `json:"base_model"`
	AdapterPath string    `json:"adapter_path"`
	DatasetHash string    `json:"dataset_hash,omitempty"`
	ActivatedAt time.Time `json:"activated_at"`
	OpSeq       uint64    `json:"op_seq,omitempty"`
}

// ActiveAdapter records the currently activated local LoRA adapter references for Tier 2
// (primary SmolLM2 + optional Phase 5 escalation Gemma 2 2B IT) and previous rollback snapshots.
type ActiveAdapter struct {
	JobID                   string       `json:"job_id,omitempty"`
	BaseModel               string       `json:"base_model,omitempty"`
	AdapterPath             string       `json:"adapter_path,omitempty"`
	DatasetHash             string       `json:"dataset_hash,omitempty"`
	ActivatedAt             time.Time    `json:"activated_at,omitempty"`
	PrimarySeq              uint64       `json:"primary_seq,omitempty"`
	EscalationSeq           uint64       `json:"escalation_seq,omitempty"`
	PrimaryMirrorHistory    string       `json:"primary_mirror_history,omitempty"`
	PrimaryMirrorSeq        uint64       `json:"primary_mirror_seq,omitempty"`
	EscalationMirrorHistory string       `json:"escalation_mirror_history,omitempty"`
	EscalationMirrorSeq     uint64       `json:"escalation_mirror_seq,omitempty"`
	Escalation              *AdapterSlot `json:"escalation,omitempty"`
	Previous                *AdapterSlot `json:"previous,omitempty"`
	PreviousEscalation      *AdapterSlot `json:"previous_escalation,omitempty"`
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

	if state.AdapterPath == "" && state.Escalation == nil && state.Previous == nil && state.PreviousEscalation == nil &&
		state.PrimarySeq == 0 && state.EscalationSeq == 0 &&
		state.PrimaryMirrorSeq == 0 && state.EscalationMirrorSeq == 0 {
		return fmt.Errorf("adapter_path is required")
	}
	return nil
}

func cloneActiveAdapter(state ActiveAdapter) ActiveAdapter {
	cp := state
	if state.Escalation != nil {
		esc := *state.Escalation
		cp.Escalation = &esc
	}
	if state.Previous != nil {
		prev := *state.Previous
		cp.Previous = &prev
	}
	if state.PreviousEscalation != nil {
		prevEsc := *state.PreviousEscalation
		cp.PreviousEscalation = &prevEsc
	}
	return cp
}

// SaveActiveAdapter validates state and atomically writes active-adapter.json (0600) inside dataDir.
func SaveActiveAdapter(dataDir string, state ActiveAdapter) error {
	if strings.TrimSpace(dataDir) == "" {
		return fmt.Errorf("data_dir is empty")
	}
	normalized := cloneActiveAdapter(state)
	if err := validateAndNormalizeManifest(&normalized); err != nil {
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
	_, err = writeActiveAdapterUnlocked(dataDir, normalized)
	return err
}

func writeActiveAdapterUnlocked(dataDir string, state ActiveAdapter) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return zero, err
	}
	payload = append(payload, '\n')
	if len(payload) > maxActiveAdapterBytes {
		return zero, fmt.Errorf("active adapter manifest (%d bytes) exceeds %d-byte limit", len(payload), maxActiveAdapterBytes)
	}

	tmp, err := os.CreateTemp(dataDir, ".active-adapter-*.tmp")
	if err != nil {
		return zero, err
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
		return zero, err
	}
	if _, err := tmp.Write(payload); err != nil {
		return zero, err
	}
	if err := tmp.Sync(); err != nil {
		return zero, err
	}
	if err := tmp.Close(); err != nil {
		return zero, err
	}
	if err := os.Rename(tmpPath, filepath.Join(dataDir, ActiveAdapterFilename)); err != nil {
		return zero, err
	}
	success = true
	return sha256.Sum256(payload), nil
}

func readAndValidateManifestWithHash(dataDir string) (ActiveAdapter, [sha256.Size]byte, bool, error) {
	var zero [sha256.Size]byte
	if strings.TrimSpace(dataDir) == "" {
		return ActiveAdapter{}, zero, false, nil
	}
	path := filepath.Join(dataDir, ActiveAdapterFilename)
	f, fi, err := feedback.OpenRegularFileNonBlocking(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ActiveAdapter{}, zero, false, nil
		}
		return ActiveAdapter{}, zero, true, fmt.Errorf("open active adapter %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	if fi.Size() > maxActiveAdapterBytes {
		return ActiveAdapter{}, zero, true, fmt.Errorf("active adapter manifest %q exceeds %d-byte limit", path, maxActiveAdapterBytes)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxActiveAdapterBytes+1))
	if err != nil {
		return ActiveAdapter{}, zero, true, fmt.Errorf("read %q: %w", path, err)
	}
	if len(data) > maxActiveAdapterBytes {
		return ActiveAdapter{}, zero, true, fmt.Errorf("active adapter manifest %q exceeds %d-byte limit", path, maxActiveAdapterBytes)
	}
	hash := sha256.Sum256(data)
	var state ActiveAdapter
	if err := json.Unmarshal(data, &state); err != nil {
		return ActiveAdapter{}, hash, true, fmt.Errorf("parse %q: %w", path, err)
	}
	if err := validateAndNormalizeManifest(&state); err != nil {
		return ActiveAdapter{}, hash, true, fmt.Errorf("invalid active adapter in %q: %w", path, err)
	}
	return state, hash, true, nil
}

// LoadActiveAdapterWithHash loads, validates, and SHA-256-hashes active-adapter.json
// from dataDir under the directory lock so readers never observe half-written transitions.
func LoadActiveAdapterWithHash(dataDir string) (ActiveAdapter, [sha256.Size]byte, bool, error) {
	var zero [sha256.Size]byte
	if strings.TrimSpace(dataDir) == "" {
		return ActiveAdapter{}, zero, false, nil
	}
	if _, err := os.Stat(dataDir); err != nil {
		if os.IsNotExist(err) {
			return ActiveAdapter{}, zero, false, nil
		}
		return ActiveAdapter{}, zero, false, err
	}
	unlockDir, err := feedback.AcquireDirLock(dataDir)
	if err != nil {
		return ActiveAdapter{}, zero, false, fmt.Errorf("lock data dir %q: %w", dataDir, err)
	}
	defer unlockDir()
	return readAndValidateManifestWithHash(dataDir)
}

// LoadActiveAdapter loads and re-validates active-adapter.json from dataDir using a
// nonblocking regular-file open so a FIFO cannot block startup.
// Returns (zero, false, nil) when the file does not exist.
func LoadActiveAdapter(dataDir string) (ActiveAdapter, bool, error) {
	state, _, exists, err := LoadActiveAdapterWithHash(dataDir)
	return state, exists, err
}

func mutateActiveAdapterUnlocked(dataDir string, fn func(*ActiveAdapter, bool) (remove bool, changed bool, err error)) (ActiveAdapter, [sha256.Size]byte, bool, error) {
	var zero [sha256.Size]byte
	if strings.TrimSpace(dataDir) == "" {
		return ActiveAdapter{}, zero, false, fmt.Errorf("data_dir is empty")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return ActiveAdapter{}, zero, false, fmt.Errorf("create data dir %q: %w", dataDir, err)
	}
	unlockDir, err := feedback.AcquireDirLock(dataDir)
	if err != nil {
		return ActiveAdapter{}, zero, false, fmt.Errorf("lock data dir %q: %w", dataDir, err)
	}
	defer unlockDir()

	cur, curHash, exists, err := readAndValidateManifestWithHash(dataDir)
	if err != nil && exists {
		return ActiveAdapter{}, zero, exists, err
	}
	remove, changed, err := fn(&cur, exists)
	if err != nil {
		return ActiveAdapter{}, zero, exists, err
	}
	if !changed {
		return cur, curHash, exists, nil
	}
	if remove {
		err := os.Remove(filepath.Join(dataDir, ActiveAdapterFilename))
		if err != nil && !os.IsNotExist(err) {
			return ActiveAdapter{}, zero, true, err
		}
		return ActiveAdapter{}, zero, false, nil
	}
	if err := validateAndNormalizeManifest(&cur); err != nil {
		return ActiveAdapter{}, zero, exists, err
	}
	writtenHash, err := writeActiveAdapterUnlocked(dataDir, cur)
	if err != nil {
		return ActiveAdapter{}, zero, exists, err
	}
	return cur, writtenHash, true, nil
}

func rollbackSlotsMatch(a, b AdapterSlot) bool {
	return a.BaseModel == b.BaseModel && a.AdapterPath == b.AdapterPath && a.JobID == b.JobID
}

// UpdateActiveAdapterSlotWithHash atomically updates either the primary or escalation slot in
// active-adapter.json, returning the updated manifest and exact SHA-256 of the written bytes.
func UpdateActiveAdapterSlotWithHash(dataDir, slot string, next AdapterSlot) (ActiveAdapter, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	normSlot, err := NormalizeSlot(slot, false)
	if err != nil {
		return ActiveAdapter{}, zero, err
	}
	if err := validateAdapterSlotStruct(&next); err != nil {
		return ActiveAdapter{}, zero, err
	}
	if next.ActivatedAt.IsZero() {
		next.ActivatedAt = time.Now().UTC()
	}
	updated, hash, _, err := mutateActiveAdapterUnlocked(dataDir, func(cur *ActiveAdapter, _ bool) (bool, bool, error) {
		switch normSlot {
		case SlotPrimary:
			if prev, ok := cur.PrimarySlot(); ok && !rollbackSlotsMatch(prev, next) {
				prevCopy := prev
				cur.Previous = &prevCopy
			}
			cur.PrimarySeq++
			next.OpSeq = cur.PrimarySeq
			cur.SetPrimarySlot(next)
		case SlotEscalation:
			if cur.Escalation != nil && !rollbackSlotsMatch(*cur.Escalation, next) {
				prevCopy := *cur.Escalation
				cur.PreviousEscalation = &prevCopy
			}
			cur.EscalationSeq++
			next.OpSeq = cur.EscalationSeq
			nextCopy := next
			cur.Escalation = &nextCopy
		}
		return false, true, nil
	})
	return updated, hash, err
}

// UpdateActiveAdapterSlot atomically updates either the primary or escalation slot in
// active-adapter.json, preserving the sibling slot and recording the displaced adapter
// for one-command rollback.
func UpdateActiveAdapterSlot(dataDir, slot string, next AdapterSlot) (ActiveAdapter, error) {
	updated, _, err := UpdateActiveAdapterSlotWithHash(dataDir, slot, next)
	return updated, err
}

// RollbackActiveAdapterSlotExpected atomically restores the prior adapter for slot ("primary" or
// "escalation"), failing with ErrRollbackTargetChanged if expected is non-nil and no longer matches
// the recorded snapshot under the directory lock.
func RollbackActiveAdapterSlotExpected(dataDir, slot string, expected *AdapterSlot) (ActiveAdapter, AdapterSlot, [sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	normSlot, err := NormalizeSlot(slot, false)
	if err != nil {
		return ActiveAdapter{}, AdapterSlot{}, zero, err
	}
	var restored AdapterSlot
	updated, hash, _, err := mutateActiveAdapterUnlocked(dataDir, func(cur *ActiveAdapter, _ bool) (bool, bool, error) {
		switch normSlot {
		case SlotPrimary:
			if cur.Previous == nil {
				return false, false, ErrNoRollbackAvailable
			}
			if expected != nil && !rollbackSlotsMatch(*cur.Previous, *expected) {
				return false, false, ErrRollbackTargetChanged
			}
			restored = *cur.Previous
			if curPrimary, ok := cur.PrimarySlot(); ok {
				prevCopy := curPrimary
				cur.Previous = &prevCopy
			} else {
				cur.Previous = nil
			}
			cur.PrimarySeq++
			restored.OpSeq = cur.PrimarySeq
			cur.SetPrimarySlot(restored)
		case SlotEscalation:
			if cur.PreviousEscalation == nil {
				return false, false, ErrNoRollbackAvailable
			}
			if expected != nil && !rollbackSlotsMatch(*cur.PreviousEscalation, *expected) {
				return false, false, ErrRollbackTargetChanged
			}
			restored = *cur.PreviousEscalation
			if cur.Escalation != nil {
				prevCopy := *cur.Escalation
				cur.PreviousEscalation = &prevCopy
			} else {
				cur.PreviousEscalation = nil
			}
			cur.EscalationSeq++
			restored.OpSeq = cur.EscalationSeq
			restoredCopy := restored
			cur.Escalation = &restoredCopy
		}
		return false, true, nil
	})
	return updated, restored, hash, err
}

// RollbackActiveAdapterSlot atomically restores the prior adapter for slot ("primary" or
// "escalation") and swaps the replaced adapter into the rollback snapshot so rollbacks
// are safely reversible.
func RollbackActiveAdapterSlot(dataDir, slot string) (ActiveAdapter, AdapterSlot, error) {
	updated, restored, _, err := RollbackActiveAdapterSlotExpected(dataDir, slot, nil)
	return updated, restored, err
}

// DeactivateActiveAdapterSlotWithHash clears the active adapter for slot ("primary", "escalation", or
// "all") while retaining its rollback snapshot (unless nothing remains active or snapshotted, in which
// case active-adapter.json is removed), returning the updated manifest, written hash, changed, hasFile, and error.
func DeactivateActiveAdapterSlotWithHash(dataDir, slot string) (ActiveAdapter, [sha256.Size]byte, bool, bool, error) {
	var zero [sha256.Size]byte
	normSlot, err := NormalizeSlot(slot, true)
	if err != nil {
		return ActiveAdapter{}, zero, false, false, err
	}
	if _, statErr := os.Stat(dataDir); statErr != nil {
		if os.IsNotExist(statErr) {
			return ActiveAdapter{}, zero, false, false, nil
		}
		return ActiveAdapter{}, zero, false, false, statErr
	}
	changed := false
	updated, hash, hasFile, err := mutateActiveAdapterUnlocked(dataDir, func(cur *ActiveAdapter, exists bool) (bool, bool, error) {
		if !exists {
			return false, false, nil
		}
		if normSlot == SlotPrimary || normSlot == SlotAll {
			if prev, ok := cur.PrimarySlot(); ok {
				prevCopy := prev
				cur.Previous = &prevCopy
				cur.ClearPrimarySlot()
				cur.PrimarySeq++
				changed = true
			}
		}
		if normSlot == SlotEscalation || normSlot == SlotAll {
			if cur.Escalation != nil {
				prevCopy := *cur.Escalation
				cur.PreviousEscalation = &prevCopy
				cur.Escalation = nil
				cur.EscalationSeq++
				changed = true
			}
		}
		if !changed {
			return false, false, nil
		}
		remove := cur.AdapterPath == "" && cur.Escalation == nil && cur.Previous == nil && cur.PreviousEscalation == nil &&
			cur.PrimarySeq == 0 && cur.EscalationSeq == 0 &&
			cur.PrimaryMirrorSeq == 0 && cur.EscalationMirrorSeq == 0
		return remove, true, nil
	})
	return updated, hash, changed, hasFile, err
}

// DeactivateActiveAdapterSlot clears the active adapter for slot ("primary", "escalation", or
// "all") while retaining its rollback snapshot (unless nothing remains active or snapshotted,
// in which case active-adapter.json is removed).
func DeactivateActiveAdapterSlot(dataDir, slot string) (ActiveAdapter, bool, error) {
	updated, _, changed, _, err := DeactivateActiveAdapterSlotWithHash(dataDir, slot)
	return updated, changed, err
}

// MirrorDaemonSlotToManifest synchronizes the local manifest's active slot to match a daemon's
// authoritative AdapterStatusResponse after a remote or separate-directory operation.
// Uses per-slot operation sequences (`OpSeq`) so rollbacks to older adapters are applied cleanly
// while delayed activations and deactivations arrive out of order without regressing state.
func MirrorDaemonSlotToManifest(dataDir, slot string, slotState *SlotStatus, fallbackModel, fallbackAdapter, fallbackJob string) (ActiveAdapter, error) {
	normSlot, err := NormalizeSlot(slot, false)
	if err != nil {
		return ActiveAdapter{}, err
	}
	bm := strings.TrimSpace(fallbackModel)
	ap := strings.TrimSpace(fallbackAdapter)
	jid := strings.TrimSpace(fallbackJob)
	var dsHash, incomingHistory string
	var swappedAt time.Time
	var incomingSeq uint64
	if slotState != nil {
		if strings.TrimSpace(slotState.BaseModel) != "" {
			bm = strings.TrimSpace(slotState.BaseModel)
		}
		ap = strings.TrimSpace(slotState.AdapterPath)
		if strings.TrimSpace(slotState.JobID) != "" {
			jid = strings.TrimSpace(slotState.JobID)
		}
		dsHash = strings.TrimSpace(slotState.DatasetHash)
		swappedAt = slotState.SwappedAt
		incomingSeq = slotState.OpSeq
		incomingHistory = strings.TrimSpace(slotState.HistoryID)
	}
	if ap == "" {
		updated, _, _, err := mutateActiveAdapterUnlocked(dataDir, func(cur *ActiveAdapter, _ bool) (bool, bool, error) {
			if normSlot == SlotEscalation {
				if incomingSeq > 0 && incomingHistory == cur.EscalationMirrorHistory && incomingSeq <= cur.EscalationMirrorSeq {
					return false, false, nil
				}
				if cur.Escalation != nil {
					prevCopy := *cur.Escalation
					cur.PreviousEscalation = &prevCopy
					cur.Escalation = nil
				}
				if incomingSeq > 0 {
					cur.EscalationMirrorHistory = incomingHistory
					cur.EscalationMirrorSeq = incomingSeq
				}
				cur.EscalationSeq++
			} else {
				if incomingSeq > 0 && incomingHistory == cur.PrimaryMirrorHistory && incomingSeq <= cur.PrimaryMirrorSeq {
					return false, false, nil
				}
				if prev, ok := cur.PrimarySlot(); ok {
					prevCopy := prev
					cur.Previous = &prevCopy
					cur.ClearPrimarySlot()
				}
				if incomingSeq > 0 {
					cur.PrimaryMirrorHistory = incomingHistory
					cur.PrimaryMirrorSeq = incomingSeq
				}
				cur.PrimarySeq++
			}
			remove := cur.AdapterPath == "" && cur.Escalation == nil && cur.Previous == nil && cur.PreviousEscalation == nil &&
				cur.PrimarySeq == 0 && cur.EscalationSeq == 0 &&
				cur.PrimaryMirrorSeq == 0 && cur.EscalationMirrorSeq == 0
			return remove, true, nil
		})
		return updated, err
	}
	next := AdapterSlot{
		JobID:       jid,
		BaseModel:   bm,
		AdapterPath: ap,
		DatasetHash: dsHash,
		ActivatedAt: swappedAt,
		OpSeq:       incomingSeq,
	}
	if err := validateAdapterSlotStruct(&next); err != nil {
		return ActiveAdapter{}, err
	}
	if next.ActivatedAt.IsZero() {
		next.ActivatedAt = time.Now().UTC()
	}
	updated, _, _, err := mutateActiveAdapterUnlocked(dataDir, func(cur *ActiveAdapter, exists bool) (bool, bool, error) {
		switch normSlot {
		case SlotPrimary:
			if incomingSeq > 0 {
				if incomingHistory == cur.PrimaryMirrorHistory && incomingSeq <= cur.PrimaryMirrorSeq {
					return false, false, nil
				}
			} else if existing, ok := cur.PrimarySlot(); ok && !existing.ActivatedAt.IsZero() && next.ActivatedAt.Before(existing.ActivatedAt) {
				return false, false, nil
			}
			if prev, ok := cur.PrimarySlot(); ok && !rollbackSlotsMatch(prev, next) {
				prevCopy := prev
				cur.Previous = &prevCopy
			}
			if incomingSeq > 0 {
				cur.PrimaryMirrorHistory = incomingHistory
				cur.PrimaryMirrorSeq = incomingSeq
			}
			cur.PrimarySeq++
			next.OpSeq = cur.PrimarySeq
			cur.SetPrimarySlot(next)
		case SlotEscalation:
			if incomingSeq > 0 {
				if incomingHistory == cur.EscalationMirrorHistory && incomingSeq <= cur.EscalationMirrorSeq {
					return false, false, nil
				}
			} else if cur.Escalation != nil && !cur.Escalation.ActivatedAt.IsZero() && next.ActivatedAt.Before(cur.Escalation.ActivatedAt) {
				return false, false, nil
			}
			if cur.Escalation != nil && !rollbackSlotsMatch(*cur.Escalation, next) {
				prevCopy := *cur.Escalation
				cur.PreviousEscalation = &prevCopy
			}
			if incomingSeq > 0 {
				cur.EscalationMirrorHistory = incomingHistory
				cur.EscalationMirrorSeq = incomingSeq
			}
			cur.EscalationSeq++
			next.OpSeq = cur.EscalationSeq
			nextCopy := next
			cur.Escalation = &nextCopy
		}
		return false, true, nil
	})
	return updated, err
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
	HistoryID           string    `json:"history_id,omitempty"`
	OpSeq               uint64    `json:"op_seq,omitempty"`
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
	Truncated         bool                `json:"truncated,omitempty"`
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
		safeErr := security.SanitizeURLError(err)
		if method != http.MethodGet {
			return AdapterStatusResponse{}, redactedTarget, fmt.Errorf("%s %s/adapter request outcome could not be confirmed (daemon state may have changed; inspect `sentinel adapter status` before retrying): %w", method, redactedTarget, safeErr)
		}
		return AdapterStatusResponse{}, redactedTarget, fmt.Errorf("%s %s/adapter: %w", method, redactedTarget, safeErr)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxActiveAdapterBytes+1))
	if readErr != nil {
		return AdapterStatusResponse{}, redactedTarget, fmt.Errorf("%s %s/adapter response could not be confirmed (daemon state may have changed; inspect `sentinel adapter status` before retrying): %w", method, redactedTarget, readErr)
	}
	if len(respBody) > maxActiveAdapterBytes {
		return AdapterStatusResponse{}, redactedTarget, fmt.Errorf("%s %s/adapter response exceeded %d-byte limit (daemon state may have changed; inspect `sentinel adapter status` before retrying)", method, redactedTarget, maxActiveAdapterBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return AdapterStatusResponse{}, redactedTarget, fmt.Errorf("%s %s/adapter returned HTTP %d: %s", method, redactedTarget, resp.StatusCode, compactErrBody(respBody, authToken))
	}
	var out AdapterStatusResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return AdapterStatusResponse{}, redactedTarget, fmt.Errorf("%s %s/adapter returned invalid JSON response (daemon state may have changed; inspect `sentinel adapter status` before retrying)", method, redactedTarget)
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
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "" {
		action = ActionActivate
	}
	var wantStatus string
	switch action {
	case ActionActivate:
		wantStatus = "activated"
	case ActionRollback:
		wantStatus = "rolled_back"
	case ActionDeactivate:
		wantStatus = "deactivated"
	default:
		return AdapterStatusResponse{}, fmt.Errorf("unsupported adapter action %q", req.Action)
	}
	if strings.TrimSpace(out.Status) != wantStatus {
		return AdapterStatusResponse{}, fmt.Errorf("POST %s/adapter returned unexpected status %q for action %q (expected %q)", redactedTarget, out.Status, action, wantStatus)
	}
	return out, nil
}

// DeactivateDaemonAdapter deactivates the active adapter for slot ("primary", "escalation", or "all")
// via `DELETE /adapter`.
func DeactivateDaemonAdapter(ctx context.Context, sentinelHTTP, authToken, slot string, allowRemote bool) (AdapterStatusResponse, error) {
	normSlot, err := NormalizeSlot(slot, true)
	if err != nil {
		return AdapterStatusResponse{}, err
	}
	out, redactedTarget, err := doDaemonAdapterRequest(ctx, http.MethodDelete, sentinelHTTP, authToken, "slot="+url.QueryEscape(normSlot), nil, allowRemote)
	if err != nil {
		return AdapterStatusResponse{}, err
	}
	if strings.TrimSpace(out.Status) != "deactivated" {
		return AdapterStatusResponse{}, fmt.Errorf("DELETE %s/adapter returned unexpected status %q (expected \"deactivated\")", redactedTarget, out.Status)
	}
	return out, nil
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
