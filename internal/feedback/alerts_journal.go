package feedback

import (
	"bufio"
	"encoding/json"
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

// Record appends newly emitted alerts into the bounded local journal using an atomic rewrite
// when trimming oldest records so partial writes never corrupt alerts.jsonl.
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

	existing, err := j.readAllLocked()
	if err != nil {
		return fmt.Errorf("read alert journal %q: %w", j.path, err)
	}
	incoming := make([]emit.Alert, len(alerts))
	for i, a := range alerts {
		if j.requireRedaction {
			a = redactAlertForPersistence(a)
		}
		incoming[i] = a
	}

	combined := append(existing, incoming...)
	if len(combined) > j.maxRecords {
		combined = combined[len(combined)-j.maxRecords:]
	}
	return j.writeAtomicLocked(combined)
}

func redactAlertForPersistence(a emit.Alert) emit.Alert {
	a.Message, _ = RedactText(a.Message)
	a.Template, _ = RedactText(a.Template)
	a.SanitizedSample, _ = RedactText(a.SanitizedSample)
	a.TriageExplanation, _ = RedactText(a.TriageExplanation)
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
	fi, err := os.Stat(j.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("alert journal %q must be a regular file", j.path)
	}
	if fi.Size() > j.maxBytes*2 {
		return nil, fmt.Errorf("alert journal %q exceeds safety cap", j.path)
	}

	f, err := os.Open(j.path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	// Size scanner token limit strictly above effectiveMaxRecordBytes (and maxBytes) so every
	// valid written record can always be read back without bufio.ErrTooLong.
	scanMax := j.effectiveMaxRecordBytes() + 4096
	if j.maxBytes > 0 && int(j.maxBytes)+4096 > scanMax {
		scanMax = int(j.maxBytes) + 4096
	}
	scanner := bufio.NewScanner(io.LimitReader(f, j.maxBytes*2+1))
	scanner.Buffer(make([]byte, 64*1024), scanMax)
	var out []emit.Alert
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var a emit.Alert
		if err := json.Unmarshal([]byte(line), &a); err == nil && a.AlertID != "" {
			out = append(out, a)
		}
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
	// Pre-serialize and validate per-record / total byte ceilings before touching disk.
	lines := make([][]byte, 0, len(alerts))
	var totalBytes int64
	for _, a := range alerts {
		b, err := json.Marshal(a)
		if err != nil {
			return fmt.Errorf("marshal alert %q: %w", a.AlertID, err)
		}
		b = append(b, '\n')
		if len(b) > recCap || int64(len(b)) > j.maxBytes {
			return fmt.Errorf("alert %q serialized size (%d bytes) exceeds journal limit (%d bytes)", a.AlertID, len(b), recCap)
		}
		lines = append(lines, b)
		totalBytes += int64(len(b))
	}
	if len(lines) == 0 {
		return nil
	}
	startIdx := 0
	for startIdx < len(lines) && totalBytes > j.maxBytes {
		totalBytes -= int64(len(lines[startIdx]))
		startIdx++
	}
	lines = lines[startIdx:]
	if len(lines) == 0 {
		return fmt.Errorf("no alerts fit within alert journal byte budget (%d bytes)", j.maxBytes)
	}

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
