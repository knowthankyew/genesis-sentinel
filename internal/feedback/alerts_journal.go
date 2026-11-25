package feedback

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/knowthankyew/genesis-sentinel/internal/emit"
)

const (
	// DefaultAlertJournalFilename is stored inside Sentinel's DataDir and removed by `sentinel burn`.
	DefaultAlertJournalFilename = "alerts.jsonl"
	// MaxAlertJournalRecords bounds locally retained recent alerts for `sentinel feedback --alert-id`.
	MaxAlertJournalRecords = 2000
	// MaxAlertJournalBytes bounds disk space used by the local alert journal.
	MaxAlertJournalBytes = 4 * 1024 * 1024 // 4 MiB
	// MaxAlertRecordBytes caps any single serialized journal record so every written record
	// remains strictly readable by FindByID and Recent.
	MaxAlertRecordBytes = 256 * 1024 // 256 KiB
)

// AlertJournal maintains a bounded local ring of recent emitted alerts on disk so
// operators can curate feedback by ID (`sentinel feedback --alert-id <ID> --label fp`).
type AlertJournal struct {
	mu               sync.Mutex
	path             string
	maxRecords       int
	maxBytes         int64
	maxRecordBytes   int
	requireRedaction bool
}

// NewAlertJournal creates a bounded alert journal backed by filepath.Join(dataDir, "alerts.jsonl")
// with mandatory PII/secret redaction enabled by default.
func NewAlertJournal(dataDir string) *AlertJournal {
	return NewAlertJournalWithRedaction(dataDir, true)
}

// NewAlertJournalWithRedaction creates a bounded alert journal backed by
// filepath.Join(dataDir, "alerts.jsonl") with configurable PII/secret scrubbing on persistence.
func NewAlertJournalWithRedaction(dataDir string, requireRedaction bool) *AlertJournal {
	return &AlertJournal{
		path:             filepath.Join(dataDir, DefaultAlertJournalFilename),
		maxRecords:       MaxAlertJournalRecords,
		maxBytes:         MaxAlertJournalBytes,
		maxRecordBytes:   MaxAlertRecordBytes,
		requireRedaction: requireRedaction,
	}
}

// Path returns the underlying alerts.jsonl file path.
func (j *AlertJournal) Path() string {
	return j.path
}

// Record appends newly emitted alerts into the bounded local journal using a temp-file
// rewrite (atomic rename on POSIX/Unix filesystems) when trimming oldest records.
// Existing I/O errors are propagated without overwriting or resetting the journal.
func (j *AlertJournal) Record(alerts ...emit.Alert) error {
	if j == nil || strings.TrimSpace(j.path) == "" || len(alerts) == 0 {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	unlock, err := acquireFileLock(j.path, true)
	if err != nil {
		return err
	}
	defer unlock()

	recCap := j.effectiveMaxRecordBytes()
	incoming := make([]emit.Alert, 0, len(alerts))
	var oversizedErrs []error
	for i, a := range alerts {
		a.AlertID = strings.TrimSpace(a.AlertID)
		if a.AlertID == "" {
			return fmt.Errorf("alert journal refuses alert %d with empty alert_id", i+1)
		}
		if j.requireRedaction {
			a = redactAlertForPersistence(a)
		}
		raw, mErr := json.Marshal(a)
		if mErr != nil {
			return fmt.Errorf("marshal alert %q: %w", a.AlertID, mErr)
		}
		if len(raw)+1 > recCap || int64(len(raw)+1) > j.maxBytes {
			oversizedErrs = append(oversizedErrs, fmt.Errorf("alert %q serialized size (%d bytes) exceeds journal limit (%d bytes)", a.AlertID, len(raw)+1, recCap))
			continue
		}
		incoming = append(incoming, a)
	}
	if len(incoming) == 0 {
		return errors.Join(oversizedErrs...)
	}

	existing, err := j.readAllLocked()
	if err != nil {
		return fmt.Errorf("read alert journal %q: %w", j.path, err)
	}

	combined := make([]emit.Alert, len(existing), len(existing)+len(incoming))
	for i, a := range existing {
		if j.requireRedaction {
			a = redactAlertForPersistence(a)
		}
		combined[i] = a
	}
	idxByID := make(map[string]int, len(combined))
	for i, a := range combined {
		idxByID[a.AlertID] = i
	}
	for _, a := range incoming {
		if idx, exists := idxByID[a.AlertID]; exists {
			// Upsert in-place so async Tier 2 enrichment updates replace the
			// initial deterministic record without duplicating AlertID rows.
			combined[idx] = a
		} else {
			idxByID[a.AlertID] = len(combined)
			combined = append(combined, a)
		}
	}
	if len(combined) > j.maxRecords {
		combined = combined[len(combined)-j.maxRecords:]
	}
	if err := j.writeAtomicLocked(combined); err != nil {
		return err
	}
	return errors.Join(oversizedErrs...)
}

// UpdateIfPresent replaces an existing alert record matching alert.AlertID in-place without
// appending or evicting newer alerts when the original alert has already aged out or been burned.
func (j *AlertJournal) UpdateIfPresent(alert emit.Alert) error {
	if j == nil || strings.TrimSpace(j.path) == "" {
		return nil
	}
	alert.AlertID = strings.TrimSpace(alert.AlertID)
	if alert.AlertID == "" {
		return fmt.Errorf("alert journal refuses update with empty alert_id")
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	unlock, err := acquireFileLock(j.path, false)
	if err != nil {
		return err
	}
	defer unlock()

	existing, err := j.readAllLocked()
	if err != nil {
		return fmt.Errorf("read alert journal %q: %w", j.path, err)
	}
	targetIdx := -1
	for i := len(existing) - 1; i >= 0; i-- {
		if existing[i].AlertID == alert.AlertID {
			targetIdx = i
			break
		}
	}
	if targetIdx < 0 {
		return nil
	}

	if j.requireRedaction {
		alert = redactAlertForPersistence(alert)
	}
	recCap := j.effectiveMaxRecordBytes()
	raw, mErr := json.Marshal(alert)
	if mErr != nil {
		return fmt.Errorf("marshal alert %q: %w", alert.AlertID, mErr)
	}
	if len(raw)+1 > recCap || int64(len(raw)+1) > j.maxBytes {
		return fmt.Errorf("alert %q serialized size (%d bytes) exceeds journal limit (%d bytes)", alert.AlertID, len(raw)+1, recCap)
	}

	updated := make([]emit.Alert, len(existing))
	for i, a := range existing {
		if j.requireRedaction {
			a = redactAlertForPersistence(a)
		}
		updated[i] = a
	}
	updated[targetIdx] = alert
	return j.writeAtomicLocked(updated)
}

func redactAlertForPersistence(a emit.Alert) emit.Alert {
	a.Service, _ = RedactText(a.Service)
	a.TraceID, _ = RedactText(a.TraceID)
	a.SourceService, _ = RedactText(a.SourceService)
	a.SourceLevel, _ = RedactText(a.SourceLevel)
	a.TemplateID, _ = RedactText(a.TemplateID)
	a.Message, _ = RedactText(a.Message)
	a.Template, _ = RedactText(a.Template)
	a.SanitizedSample, _ = RedactText(a.SanitizedSample)
	a.TriageExplanation, _ = RedactText(a.TriageExplanation)
	a.TriageModel, _ = RedactText(a.TriageModel)
	a.TriageAdapter, _ = RedactText(a.TriageAdapter)
	if len(a.RuleIDs) > 0 {
		out := make([]string, len(a.RuleIDs))
		for i, r := range a.RuleIDs {
			out[i], _ = RedactText(r)
		}
		a.RuleIDs = out
	}
	if len(a.Categories) > 0 {
		out := make([]string, len(a.Categories))
		for i, c := range a.Categories {
			out[i], _ = RedactText(c)
		}
		a.Categories = out
	}
	if len(a.InjectionSignals) > 0 {
		out := make([]string, len(a.InjectionSignals))
		for i, s := range a.InjectionSignals {
			out[i], _ = RedactText(s)
		}
		a.InjectionSignals = out
	}
	if len(a.TopSurprisalFeatures) > 0 {
		out := make(map[string]float64, len(a.TopSurprisalFeatures))
		for k, v := range a.TopSurprisalFeatures {
			rk, findings := RedactText(k)
			// Omit feature keys that required redaction so distinct redacted keys never
			// collide nondeterministically on a shared placeholder.
			if len(findings) > 0 || rk != k {
				continue
			}
			out[k] = v
		}
		if len(out) == 0 {
			a.TopSurprisalFeatures = nil
		} else {
			a.TopSurprisalFeatures = out
		}
	}
	return a
}

// FindByID searches the local alert journal for the most recent alert matching alertID.
func (j *AlertJournal) FindByID(alertID string) (emit.Alert, bool, error) {
	if j == nil || strings.TrimSpace(alertID) == "" {
		return emit.Alert{}, false, nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	unlock, err := acquireFileLock(j.path, false)
	if err != nil {
		return emit.Alert{}, false, err
	}
	defer unlock()

	all, err := j.readAllLocked()
	if err != nil {
		return emit.Alert{}, false, err
	}
	target := strings.TrimSpace(alertID)
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].AlertID == target {
			return all[i], true, nil
		}
	}
	return emit.Alert{}, false, nil
}

// Recent returns up to limit most recent alerts from the journal (newest first).
func (j *AlertJournal) Recent(limit int) ([]emit.Alert, error) {
	if j == nil {
		return nil, nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	unlock, err := acquireFileLock(j.path, false)
	if err != nil {
		return nil, err
	}
	defer unlock()

	all, err := j.readAllLocked()
	if err != nil {
		return nil, err
	}
	if limit <= 0 || limit > len(all) {
		limit = len(all)
	}
	out := make([]emit.Alert, 0, limit)
	for i := len(all) - 1; i >= len(all)-limit; i-- {
		out = append(out, all[i])
	}
	return out, nil
}

func (j *AlertJournal) effectiveMaxRecordBytes() int {
	recCap := j.maxRecordBytes
	if recCap <= 0 {
		recCap = MaxAlertRecordBytes
	}
	if j.maxBytes > 0 && int64(recCap) > j.maxBytes {
		recCap = int(j.maxBytes)
	}
	return recCap
}

func (j *AlertJournal) readAllLocked() ([]emit.Alert, error) {
	f, fi, err := OpenRegularFileNonBlocking(j.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("alert journal %w", err)
	}
	defer func() { _ = f.Close() }()
	if fi.Size() > j.maxBytes*2 {
		return nil, fmt.Errorf("alert journal %q exceeds safety cap", j.path)
	}

	// Size scanner token limit strictly above effectiveMaxRecordBytes (and maxBytes) so every
	// valid written record can always be read back without bufio.ErrTooLong.
	scanMax := j.effectiveMaxRecordBytes() + 4096
	if j.maxBytes > 0 && int(j.maxBytes)+4096 > scanMax {
		scanMax = int(j.maxBytes) + 4096
	}
	scanner := bufio.NewScanner(io.LimitReader(f, j.maxBytes*2+1))
	scanner.Buffer(make([]byte, 64*1024), scanMax)
	var out []emit.Alert
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var a emit.Alert
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			return nil, fmt.Errorf("alert journal %q line %d: malformed JSON: %w", j.path, lineNo, err)
		}
		if strings.TrimSpace(a.AlertID) == "" {
			return nil, fmt.Errorf("alert journal %q line %d: missing alert_id", j.path, lineNo)
		}
		if j.maxRecords > 0 && len(out) >= j.maxRecords {
			return nil, fmt.Errorf("alert journal %q exceeds safety cap of %d records", j.path, j.maxRecords)
		}
		out = append(out, a)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (j *AlertJournal) writeAtomicLocked(alerts []emit.Alert) error {
	dir := filepath.Dir(j.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	recCap := j.effectiveMaxRecordBytes()
	// Serialize from newest to oldest, enforcing per-record limits and capping the
	// total encoded payload rows kept for writing at j.maxBytes.
	keptRev := make([][]byte, 0, min(len(alerts), 64))
	var totalBytes int64
	for i := len(alerts) - 1; i >= 0; i-- {
		a := alerts[i]
		b, err := json.Marshal(a)
		if err != nil {
			return fmt.Errorf("marshal alert %q: %w", a.AlertID, err)
		}
		b = append(b, '\n')
		if len(b) > recCap || int64(len(b)) > j.maxBytes {
			// A previously stored legacy row may expand past recCap if redaction is enabled
			// later; skip that retained row instead of permanently blocking new alert writes.
			continue
		}
		if totalBytes+int64(len(b)) > j.maxBytes {
			break
		}
		keptRev = append(keptRev, b)
		totalBytes += int64(len(b))
	}
	if len(keptRev) == 0 {
		return fmt.Errorf("no alerts fit within alert journal byte budget (%d bytes)", j.maxBytes)
	}
	// Reverse back into chronological (oldest -> newest) order for disk persistence.
	for l, r := 0, len(keptRev)-1; l < r; l, r = l+1, r-1 {
		keptRev[l], keptRev[r] = keptRev[r], keptRev[l]
	}
	lines := keptRev

	tmp, err := os.CreateTemp(dir, ".alerts-*.tmp")
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
	bw := bufio.NewWriterSize(tmp, 32*1024)
	for _, l := range lines {
		if _, err := bw.Write(l); err != nil {
			return err
		}
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, j.path); err != nil {
		return err
	}
	success = true
	return nil
}
