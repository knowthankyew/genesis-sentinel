package feedback

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/emit"
	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/triage"
)

const (
	// DefaultFeedbackFilename is the primary Sentinel-owned feedback JSONL queue inside FeedbackDir.
	DefaultFeedbackFilename = "sentinel-feedback.jsonl"
	// MaxFieldChars mirrors ml/src/FtaaSService.Api/Services/DatasetService.cs per-field ceiling.
	MaxFieldChars = 10000
	// MinPromptChars mirrors DatasetService.cs minimum prompt length.
	MinPromptChars = 3
)

var safeSlugRe = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

// ExportSummary describes a finalized FTaaS-compatible JSONL dataset export.
type ExportSummary struct {
	Path        string         `json:"path"`
	RecordCount int            `json:"record_count"`
	ByteSize    int64          `json:"byte_size"`
	SHA256      string         `json:"sha256"`
	ClassCounts map[string]int `json:"class_counts,omitempty"`
}

// StoreStats summarizes curated operator feedback stored on disk.
type StoreStats struct {
	Path        string         `json:"path"`
	Exists      bool           `json:"exists"`
	RecordCount int            `json:"record_count"`
	ByteSize    int64          `json:"byte_size"`
	ClassCounts map[string]int `json:"class_counts"`
}

// ValidationSummary reports pre-upload FTaaS JSONL dataset verification metrics.
type ValidationSummary struct {
	Path        string `json:"path"`
	RecordCount int    `json:"record_count"`
	ByteSize    int64  `json:"byte_size"`
	SHA256      string `json:"sha256"`
}

// ftaasRecord is the minimal normalized wire format expected by FTaaS DatasetService.cs.
type ftaasRecord struct {
	Prompt     string  `json:"prompt"`
	Completion string  `json:"completion"`
	Weight     float64 `json:"weight,omitempty"`
}

// Store manages Sentinel-owned redacted feedback JSONL files under FeedbackDir,
// strictly adhering to the BurnLocalState filename contract and FTaaS size/record ceilings.
type Store struct {
	mu               sync.Mutex
	dir              string
	requireRedaction bool
	maxRecords       int
	maxFileBytes     int64
}

// NewStore builds a feedback dataset store rooted at feedbackDir.
func NewStore(feedbackDir string, requireRedaction bool) *Store {
	return &Store{
		dir:              feedbackDir,
		requireRedaction: requireRedaction,
		maxRecords:       config.DefaultMaxTrainingRecords,
		maxFileBytes:     config.DefaultMaxTrainingFileBytes,
	}
}

// NamedFilename returns a BurnLocalState-compatible Sentinel feedback filename for slug
// (or DefaultFeedbackFilename when slug is empty).
func NamedFilename(slug string) (string, error) {
	trimmed := strings.TrimSpace(slug)
	if trimmed == "" {
		return DefaultFeedbackFilename, nil
	}
	if !safeSlugRe.MatchString(trimmed) {
		return "", fmt.Errorf("invalid dataset name %q (allowed: 1-64 ASCII letters, digits, '-' or '_')", slug)
	}
	return "sentinel-feedback-" + trimmed + ".jsonl", nil
}

// PathFor resolves filename strictly inside Store.dir after validating it matches Sentinel's
// owned feedback filename contract (never allowing path traversal).
func (s *Store) PathFor(filename string) (string, error) {
	if strings.TrimSpace(s.dir) == "" {
		return "", fmt.Errorf("feedback directory is empty")
	}
	if filename == "" {
		filename = DefaultFeedbackFilename
	}
	if filepath.Base(filename) != filename || strings.ContainsAny(filename, `/\`) {
		return "", fmt.Errorf("feedback filename %q must not contain path separators", filename)
	}
	if !isSentinelFeedbackFilename(filename) {
		return "", fmt.Errorf("feedback filename %q must follow sentinel-feedback[-<name>].jsonl naming", filename)
	}
	return filepath.Join(s.dir, filename), nil
}

func isSentinelFeedbackFilename(name string) bool {
	if name == DefaultFeedbackFilename {
		return true
	}
	if strings.HasPrefix(name, "sentinel-feedback-") && strings.HasSuffix(name, ".jsonl") {
		mid := strings.TrimSuffix(strings.TrimPrefix(name, "sentinel-feedback-"), ".jsonl")
		return safeSlugRe.MatchString(mid)
	}
	return false
}

// RecordFromAlert converts an emitted Sentinel Alert and operator verdict label
// ("tp", "fp", canonical taxonomy class, or custom uppercase tag) into a redacted,
// FTaaS-ready FeedbackRecord.
func RecordFromAlert(
	alert emit.Alert,
	label string,
	note string,
	weight float64,
	maxPromptBytes int,
	requireRedaction bool,
) (model.FeedbackRecord, []string, error) {
	resolvedClass, err := ResolveOperatorLabel(label, alert.Categories)
	if err != nil {
		return model.FeedbackRecord{}, nil, err
	}
	if weight == 0 {
		weight = 1.0
	}
	if math.IsNaN(weight) || math.IsInf(weight, 0) || weight <= 0 {
		return model.FeedbackRecord{}, nil, fmt.Errorf("invalid feedback weight %v: must be positive and finite", weight)
	}

	prompt, _, _ := triage.BuildTriagePrompt(triage.PromptInput{
		Service:              alert.SourceService,
		Level:                alert.SourceLevel,
		TemplateID:           alert.TemplateID,
		Template:             alert.Template,
		SampleLine:           alert.SanitizedSample,
		Count:                alert.Count,
		SampleEntropy:        alert.SampleEntropy,
		RuleIDs:              alert.RuleIDs,
		Categories:           alert.Categories,
		SurprisalNats:        alert.SurprisalNats,
		SurprisalThreshold:   alert.SurprisalThreshold,
		TopSurprisalFeatures: alert.TopSurprisalFeatures,
		InjectionSuspected:   alert.InjectionSuspected,
		InjectionSignals:     alert.InjectionSignals,
	}, maxPromptBytes)

	exp := strings.TrimSpace(note)
	if exp == "" {
		if resolvedClass == triage.ClassBenignNoise {
			exp = fmt.Sprintf("Operator marked alert %s on service=%s as benign noise.", alert.AlertID, alert.SourceService)
		} else {
			exp = fmt.Sprintf("Operator confirmed %s on service=%s (%s).", resolvedClass, alert.SourceService, strings.Join(alert.RuleIDs, ","))
		}
	}
	completion := triage.FormatCanonicalCompletion(resolvedClass, triage.DefaultSeverityForClass(resolvedClass), triage.DefaultMitreForClass(resolvedClass), exp)

	rec := model.FeedbackRecord{
		Prompt:     prompt,
		Completion: completion,
		Weight:     weight,
		Label:      resolvedClass,
		Redacted:   requireRedaction,
		ReviewedAt: time.Now().UTC(),
	}
	return PrepareRecord(rec, requireRedaction)
}

// ResolveOperatorLabel interprets operator feedback labels:
//   - "tp" / "true_positive" -> inferred class from alert categories
//   - "fp" / "false_positive" -> BENIGN-NOISE
//   - canonical taxonomy class or custom operator tag (e.g. BENIGN-CRON)
func ResolveOperatorLabel(rawLabel string, alertCategories []string) (string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(rawLabel))
	if trimmed == "" {
		return "", fmt.Errorf("feedback label is required (e.g. tp, fp, BENIGN-NOISE, AUTH-BRUTEFORCE)")
	}
	if trimmed == "tp" || trimmed == "true_positive" || trimmed == "true-positive" {
		return triage.InferClassFromCategories(alertCategories), nil
	}
	if cls, ok := triage.NormalizeFeedbackClass(rawLabel); ok {
		return cls, nil
	}
	return "", fmt.Errorf("invalid feedback label %q: expected tp, fp, a triage class, or an uppercase tag [A-Z0-9-]", rawLabel)
}

// PrepareRecord validates field lengths/weights and, when requireRedaction is true,
// applies mandatory PII/secret scrubbing followed by a fail-closed residual PII scan.
func PrepareRecord(rec model.FeedbackRecord, requireRedaction bool) (model.FeedbackRecord, []string, error) {
	var redactedKinds []string
	if requireRedaction {
		var fp, fc []string
		rec.Prompt, fp = RedactText(rec.Prompt)
		rec.Completion, fc = RedactText(rec.Completion)
		redactedKinds = append(redactedKinds, fp...)
		redactedKinds = append(redactedKinds, fc...)
		rec.Redacted = true
	}

	rec.Prompt = strings.TrimSpace(rec.Prompt)
	rec.Completion = strings.TrimSpace(rec.Completion)

	if len(rec.Prompt) < MinPromptChars || len(rec.Completion) < 1 {
		return model.FeedbackRecord{}, redactedKinds, fmt.Errorf("feedback record has empty or overly short prompt/completion")
	}
	if len(rec.Prompt) > MaxFieldChars || len(rec.Completion) > MaxFieldChars {
		return model.FeedbackRecord{}, redactedKinds, fmt.Errorf("feedback record exceeds FTaaS %d-character per-field limit", MaxFieldChars)
	}
	if rec.Weight == 0 {
		rec.Weight = 1.0
	}
	if math.IsNaN(rec.Weight) || math.IsInf(rec.Weight, 0) || rec.Weight <= 0 {
		return model.FeedbackRecord{}, redactedKinds, fmt.Errorf("feedback record has invalid weight %v", rec.Weight)
	}

	if requireRedaction {
		if cat, found := ScanForPII(rec.Prompt); found {
			return model.FeedbackRecord{}, redactedKinds, fmt.Errorf("refusing feedback record: residual %s detected in prompt after redaction", cat)
		}
		if cat, found := ScanForPII(rec.Completion); found {
			return model.FeedbackRecord{}, redactedKinds, fmt.Errorf("refusing feedback record: residual %s detected in completion after redaction", cat)
		}
	}

	if rec.ReviewedAt.IsZero() {
		rec.ReviewedAt = time.Now().UTC()
	}
	return rec, redactedKinds, nil
}

// Append validates, redacts (when configured), and atomically appends records to filename inside FeedbackDir.
func (s *Store) Append(filename string, recs ...model.FeedbackRecord) (int, error) {
	if len(recs) == 0 {
		return 0, nil
	}
	path, err := s.PathFor(filename)
	if err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := readFeedbackRecordsLocked(path, s.maxRecords, s.maxFileBytes)
	if err != nil {
		return 0, err
	}

	prepared := make([]model.FeedbackRecord, 0, len(recs))
	for i, r := range recs {
		pr, _, prepErr := PrepareRecord(r, s.requireRedaction)
		if prepErr != nil {
			return 0, fmt.Errorf("record %d: %w", i+1, prepErr)
		}
		prepared = append(prepared, pr)
	}

	combined := append(existing, prepared...)
	if len(combined) > s.maxRecords {
		return 0, fmt.Errorf("feedback queue would exceed FTaaS limit of %d records (%d)", s.maxRecords, len(combined))
	}
	if _, err := writeRecordsAtomic(path, combined, false, s.maxRecords, s.maxFileBytes); err != nil {
		return 0, err
	}
	return len(combined), nil
}

// ReadAll loads all FeedbackRecords from filename inside FeedbackDir (returns nil, nil if absent).
func (s *Store) ReadAll(filename string) ([]model.FeedbackRecord, error) {
	path, err := s.PathFor(filename)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return readFeedbackRecordsLocked(path, s.maxRecords, s.maxFileBytes)
}

// Stats returns record and class counts for filename inside FeedbackDir.
func (s *Store) Stats(filename string) (StoreStats, error) {
	path, err := s.PathFor(filename)
	if err != nil {
		return StoreStats{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	st := StoreStats{
		Path:        path,
		ClassCounts: make(map[string]int),
	}
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return st, nil
		}
		return st, err
	}
	st.Exists = true
	st.ByteSize = fi.Size()

	recs, err := readFeedbackRecordsLocked(path, s.maxRecords, s.maxFileBytes)
	if err != nil {
		return st, err
	}
	st.RecordCount = len(recs)
	for _, r := range recs {
		lbl := r.Label
		if lbl == "" {
			lbl = inferLabelFromCompletion(r.Completion)
		}
		st.ClassCounts[lbl]++
	}
	return st, nil
}

// ExportFTaaS writes a normalized, redacted FTaaS JSONL dataset (`{"prompt","completion"[,"weight"]}`)
// combining curated records from sourceFilename with optional deterministic synthetic seed records.
func (s *Store) ExportFTaaS(sourceFilename, outPath string, includeSeedPerClass int, seed uint64) (ExportSummary, error) {
	if strings.TrimSpace(outPath) == "" {
		return ExportSummary{}, fmt.Errorf("export output path is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var all []model.FeedbackRecord
	if sourceFilename != "" {
		srcPath, err := s.PathFor(sourceFilename)
		if err != nil {
			return ExportSummary{}, err
		}
		curated, err := readFeedbackRecordsLocked(srcPath, s.maxRecords, s.maxFileBytes)
		if err != nil {
			return ExportSummary{}, err
		}
		all = append(all, curated...)
	}
	if includeSeedPerClass > 0 {
		all = append(all, GenerateSeedDataset(includeSeedPerClass, seed)...)
	}
	if len(all) == 0 {
		return ExportSummary{}, fmt.Errorf("no feedback records available to export (add feedback or pass --include-seed)")
	}

	cleaned := make([]model.FeedbackRecord, 0, len(all))
	classCounts := make(map[string]int)
	for i, r := range all {
		pr, _, err := PrepareRecord(r, s.requireRedaction)
		if err != nil {
			return ExportSummary{}, fmt.Errorf("export record %d: %w", i+1, err)
		}
		lbl := pr.Label
		if lbl == "" {
			lbl = inferLabelFromCompletion(pr.Completion)
		}
		classCounts[lbl]++
		cleaned = append(cleaned, pr)
	}

	sum, err := writeRecordsAtomic(outPath, cleaned, true, s.maxRecords, s.maxFileBytes)
	if err != nil {
		return ExportSummary{}, err
	}
	sum.ClassCounts = classCounts
	return sum, nil
}

// WriteFTaaSDataset writes a slice of FeedbackRecords directly to outPath in normalized FTaaS JSONL format.
func WriteFTaaSDataset(outPath string, records []model.FeedbackRecord, requireRedaction bool) (ExportSummary, error) {
	if len(records) == 0 {
		return ExportSummary{}, fmt.Errorf("cannot write empty FTaaS dataset")
	}
	cleaned := make([]model.FeedbackRecord, 0, len(records))
	classCounts := make(map[string]int)
	for i, r := range records {
		pr, _, err := PrepareRecord(r, requireRedaction)
		if err != nil {
			return ExportSummary{}, fmt.Errorf("record %d: %w", i+1, err)
		}
		lbl := pr.Label
		if lbl == "" {
			lbl = inferLabelFromCompletion(pr.Completion)
		}
		classCounts[lbl]++
		cleaned = append(cleaned, pr)
	}
	sum, err := writeRecordsAtomic(outPath, cleaned, true, config.DefaultMaxTrainingRecords, config.DefaultMaxTrainingFileBytes)
	if err != nil {
		return ExportSummary{}, err
	}
	sum.ClassCounts = classCounts
	return sum, nil
}

// ValidateJSONLFile streams and verifies a JSONL file against FTaaS ingestion constraints
// (25 MB size ceiling, 50,000 record ceiling, required string prompt/completion within
// 3..10,000 / 1..10,000 chars, positive finite weight, and fail-closed PII/secret scanning
// when requirePIIScan is true).
func ValidateJSONLFile(path string, requirePIIScan bool) (ValidationSummary, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return ValidationSummary{}, fmt.Errorf("stat dataset %q: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return ValidationSummary{}, fmt.Errorf("dataset %q must be a regular file", path)
	}
	if fi.Size() <= 0 {
		return ValidationSummary{}, fmt.Errorf("dataset %q is empty", path)
	}
	if fi.Size() > config.DefaultMaxTrainingFileBytes {
		return ValidationSummary{}, fmt.Errorf("dataset %q (%d bytes) exceeds FTaaS ceiling of %d bytes",
			path, fi.Size(), config.DefaultMaxTrainingFileBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return ValidationSummary{}, fmt.Errorf("open dataset %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	hasher := sha256.New()
	limited := io.LimitReader(f, config.DefaultMaxTrainingFileBytes+1)
	tee := io.TeeReader(limited, hasher)
	scanner := bufio.NewScanner(tee)
	scanner.Buffer(make([]byte, 64*1024), 512*1024)

	var (
		count     int
		totalRead int64
	)
	for scanner.Scan() {
		lineBytes := scanner.Bytes()
		totalRead += int64(len(lineBytes)) + 1
		if totalRead > config.DefaultMaxTrainingFileBytes+1 {
			return ValidationSummary{}, fmt.Errorf("dataset %q grew past FTaaS ceiling of %d bytes during read",
				path, config.DefaultMaxTrainingFileBytes)
		}
		line := strings.TrimSpace(string(lineBytes))
		if line == "" {
			continue
		}
		count++
		if count > config.DefaultMaxTrainingRecords {
			return ValidationSummary{}, fmt.Errorf("dataset %q exceeds FTaaS ceiling of %d records",
				path, config.DefaultMaxTrainingRecords)
		}
		if requirePIIScan {
			if cat, found := ScanForPII(line); found {
				return ValidationSummary{}, fmt.Errorf("dataset %q line %d blocked by pre-upload PII/secret check: detected %s",
					path, count, cat)
			}
		}

		var raw map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			return ValidationSummary{}, fmt.Errorf("dataset %q line %d invalid JSON: %w", path, count, err)
		}
		promptRaw, okP := raw["prompt"]
		compRaw, okC := raw["completion"]
		if !okP || !okC {
			return ValidationSummary{}, fmt.Errorf("dataset %q line %d missing required prompt/completion fields", path, count)
		}
		var prompt, completion string
		if err := json.Unmarshal(promptRaw, &prompt); err != nil {
			return ValidationSummary{}, fmt.Errorf("dataset %q line %d prompt must be a JSON string", path, count)
		}
		if err := json.Unmarshal(compRaw, &completion); err != nil {
			return ValidationSummary{}, fmt.Errorf("dataset %q line %d completion must be a JSON string", path, count)
		}
		prompt = strings.TrimSpace(prompt)
		completion = strings.TrimSpace(completion)
		if len(prompt) < MinPromptChars || len(completion) < 1 {
			return ValidationSummary{}, fmt.Errorf("dataset %q line %d prompt/completion too short", path, count)
		}
		if len(prompt) > MaxFieldChars || len(completion) > MaxFieldChars {
			return ValidationSummary{}, fmt.Errorf("dataset %q line %d exceeds %d-character field limit", path, count, MaxFieldChars)
		}
		if wRaw, hasW := raw["weight"]; hasW && string(wRaw) != "null" {
			var w float64
			if err := json.Unmarshal(wRaw, &w); err != nil || math.IsNaN(w) || math.IsInf(w, 0) || w <= 0 {
				return ValidationSummary{}, fmt.Errorf("dataset %q line %d has invalid weight", path, count)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return ValidationSummary{}, fmt.Errorf("scan dataset %q: %w", path, err)
	}
	if count == 0 {
		return ValidationSummary{}, fmt.Errorf("dataset %q contains 0 valid JSONL records", path)
	}

	return ValidationSummary{
		Path:        path,
		RecordCount: count,
		ByteSize:    fi.Size(),
		SHA256:      hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

func readFeedbackRecordsLocked(path string, maxRecords int, maxBytes int64) ([]model.FeedbackRecord, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat feedback file %q: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("feedback file %q must be a regular file", path)
	}
	if fi.Size() > maxBytes {
		return nil, fmt.Errorf("feedback file %q (%d bytes) exceeds %d-byte limit", path, fi.Size(), maxBytes)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(io.LimitReader(f, maxBytes+1))
	scanner.Buffer(make([]byte, 64*1024), 512*1024)
	var out []model.FeedbackRecord
	lineNo := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineNo++
		if len(out) >= maxRecords {
			return nil, fmt.Errorf("feedback file %q exceeds %d-record limit", path, maxRecords)
		}
		var rec model.FeedbackRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("parse feedback file %q line %d: %w", path, lineNo, err)
		}
		out = append(out, rec)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read feedback file %q: %w", path, err)
	}
	return out, nil
}

func writeRecordsAtomic(path string, records []model.FeedbackRecord, ftaasFormat bool, maxRecords int, maxBytes int64) (ExportSummary, error) {
	if len(records) > maxRecords {
		return ExportSummary{}, fmt.Errorf("record count %d exceeds FTaaS ceiling of %d", len(records), maxRecords)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return ExportSummary{}, fmt.Errorf("create directory %q: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".sentinel-feedback-*.tmp")
	if err != nil {
		return ExportSummary{}, fmt.Errorf("create temp feedback file: %w", err)
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
		return ExportSummary{}, err
	}

	hasher := sha256.New()
	bw := bufio.NewWriterSize(io.MultiWriter(tmp, hasher), 64*1024)
	var totalBytes int64

	for _, r := range records {
		var payload []byte
		if ftaasFormat {
			fr := ftaasRecord{
				Prompt:     r.Prompt,
				Completion: r.Completion,
			}
			if r.Weight > 0 && math.Abs(r.Weight-1.0) > 1e-6 {
				fr.Weight = r.Weight
			}
			payload, err = json.Marshal(fr)
		} else {
			payload, err = json.Marshal(r)
		}
		if err != nil {
			return ExportSummary{}, fmt.Errorf("marshal feedback record: %w", err)
		}
		payload = append(payload, '\n')
		totalBytes += int64(len(payload))
		if totalBytes > maxBytes {
			return ExportSummary{}, fmt.Errorf("serialized dataset exceeds FTaaS %d-byte limit", maxBytes)
		}
		if _, err := bw.Write(payload); err != nil {
			return ExportSummary{}, err
		}
	}

	if err := bw.Flush(); err != nil {
		return ExportSummary{}, err
	}
	if err := tmp.Sync(); err != nil {
		return ExportSummary{}, err
	}
	if err := tmp.Close(); err != nil {
		return ExportSummary{}, err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return ExportSummary{}, errors.Join(fmt.Errorf("commit feedback file %q: %w", path, err), os.Remove(tmpPath))
	}
	success = true

	return ExportSummary{
		Path:        path,
		RecordCount: len(records),
		ByteSize:    totalBytes,
		SHA256:      hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

func inferLabelFromCompletion(comp string) string {
	v, _ := triage.ParseCompletion(comp, "", "", "", false, nil)
	return v.Label
}
