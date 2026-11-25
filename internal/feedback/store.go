package feedback

import (
	"bufio"
	"bytes"
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
	"unicode/utf8"

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
	// MaxFeedbackRecordBytes bounds any single serialized feedback JSONL row so every written
	// record stays strictly below the reader scanner limit.
	MaxFeedbackRecordBytes = 256 * 1024
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

// IsOwnedFeedbackFilename reports whether name matches Sentinel's owned feedback queue
// or writer temporary filename grammar (exact safeSlugRe slugs; never unrelated user files
// such as "sentinel-feedback-team notes.jsonl").
func IsOwnedFeedbackFilename(name string) bool {
	if name == DefaultFeedbackFilename || name == DefaultFeedbackFilename+".tmp" {
		return true
	}
	if strings.HasPrefix(name, "sentinel-feedback-") {
		if strings.HasSuffix(name, ".jsonl") {
			mid := strings.TrimSuffix(strings.TrimPrefix(name, "sentinel-feedback-"), ".jsonl")
			return safeSlugRe.MatchString(mid)
		}
		if strings.HasSuffix(name, ".jsonl.tmp") {
			mid := strings.TrimSuffix(strings.TrimPrefix(name, "sentinel-feedback-"), ".jsonl.tmp")
			return safeSlugRe.MatchString(mid)
		}
	}
	return strings.HasPrefix(name, ".sentinel-feedback-") && strings.HasSuffix(name, ".tmp")
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

	if strings.TrimSpace(rec.Label) != "" {
		normLabel, ok := triage.NormalizeFeedbackClass(rec.Label)
		if !ok {
			return model.FeedbackRecord{}, redactedKinds, fmt.Errorf("feedback record has invalid label %q (expected canonical triage class or uppercase tag [A-Z0-9-])", rec.Label)
		}
		rec.Label = normLabel
	}

	if err := validateFieldLengths(rec.Prompt, rec.Completion); err != nil {
		return model.FeedbackRecord{}, redactedKinds, fmt.Errorf("feedback record %w", err)
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

	unlock, err := acquireFileLock(path, true)
	if err != nil {
		return 0, err
	}
	defer unlock()

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

	unlock, err := acquireFileLock(path, false)
	if err != nil {
		return nil, err
	}
	defer unlock()

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

	unlock, err := acquireFileLock(path, false)
	if err != nil {
		return StoreStats{}, err
	}
	defer unlock()

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

	// Reject overwriting the primary curated queue or any existing curated queue under FeedbackDir.
	if defaultPath, err := s.PathFor(DefaultFeedbackFilename); err == nil && sameTargetPath(defaultPath, outPath) {
		return ExportSummary{}, fmt.Errorf("refusing to export FTaaS dataset over curated feedback queue %q (choose a separate output path)", defaultPath)
	}
	if s.isExistingCuratedQueue(outPath) {
		return ExportSummary{}, fmt.Errorf("refusing to export FTaaS dataset over existing curated feedback queue %q (choose a separate output path)", outPath)
	}

	var all []model.FeedbackRecord
	if sourceFilename != "" {
		srcPath, err := s.PathFor(sourceFilename)
		if err != nil {
			return ExportSummary{}, err
		}
		if sameTargetPath(srcPath, outPath) {
			return ExportSummary{}, fmt.Errorf("refusing to export FTaaS dataset over curated source queue %q (choose a separate output path)", srcPath)
		}
		unlockSrc, err := acquireFileLock(srcPath, false)
		if err != nil {
			return ExportSummary{}, err
		}
		curated, readErr := readFeedbackRecordsLocked(srcPath, s.maxRecords, s.maxFileBytes)
		unlockSrc()
		if readErr != nil {
			return ExportSummary{}, readErr
		}
		all = append(all, curated...)
	}
	if includeSeedPerClass > 0 {
		numClasses := len(triage.AllClasses())
		remaining := s.maxRecords - len(all)
		if numClasses == 0 || remaining < 0 || includeSeedPerClass > remaining/numClasses {
			return ExportSummary{}, fmt.Errorf("export would exceed FTaaS limit of %d records (existing=%d, requested seed=%d/class across %d classes)",
				s.maxRecords, len(all), includeSeedPerClass, numClasses)
		}
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

	unlockOut, err := acquireFileLock(outPath, true)
	if err != nil {
		return ExportSummary{}, err
	}
	defer unlockOut()

	// Recheck curated queue ownership while holding the output directory lock so a concurrent
	// Store.Append cannot create a curated queue at outPath between precheck and rename.
	if s.isExistingCuratedQueue(outPath) {
		return ExportSummary{}, fmt.Errorf("refusing to export FTaaS dataset over existing curated feedback queue %q (choose a separate output path)", outPath)
	}

	sum, err := writeRecordsAtomic(outPath, cleaned, true, s.maxRecords, s.maxFileBytes)
	if err != nil {
		return ExportSummary{}, err
	}
	sum.ClassCounts = classCounts
	return sum, nil
}

// WriteFTaaSDataset writes a slice of FeedbackRecords directly to outPath in normalized FTaaS JSONL format,
// refusing to overwrite the primary curated queue or any existing curated queue file.
func WriteFTaaSDataset(outPath string, records []model.FeedbackRecord, requireRedaction bool) (ExportSummary, error) {
	if strings.TrimSpace(outPath) == "" {
		return ExportSummary{}, fmt.Errorf("dataset output path is required")
	}
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

	unlockOut, err := acquireFileLock(outPath, true)
	if err != nil {
		return ExportSummary{}, err
	}
	defer unlockOut()

	if filepath.Base(outPath) == DefaultFeedbackFilename || isExistingCuratedQueueFile(outPath) {
		return ExportSummary{}, fmt.Errorf("refusing to overwrite curated feedback queue %q with FTaaS export dataset", outPath)
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
// 3..10,000 / 1..10,000 decoded characters, positive finite weight, and fail-closed PII/secret
// scanning of both raw JSON lines and decoded fields when requirePIIScan is true).
func ValidateJSONLFile(path string, requirePIIScan bool) (ValidationSummary, error) {
	f, fi, err := OpenRegularFileNonBlocking(path)
	if err != nil {
		return ValidationSummary{}, fmt.Errorf("dataset %w", err)
	}
	defer func() { _ = f.Close() }()

	if fi.Size() <= 0 {
		return ValidationSummary{}, fmt.Errorf("dataset %q is empty", path)
	}
	if fi.Size() > config.DefaultMaxTrainingFileBytes {
		return ValidationSummary{}, fmt.Errorf("dataset %q (%d bytes) exceeds FTaaS ceiling of %d bytes",
			path, fi.Size(), config.DefaultMaxTrainingFileBytes)
	}

	return validateJSONLStream(f, path, requirePIIScan)
}

// ReadAndValidateJSONLFile reads a size-bounded snapshot of path once from the open file
// descriptor, validates that exact byte slice against FTaaS schema/size/PII constraints, and
// returns both the validated snapshot bytes and ValidationSummary so upload callers cannot
// suffer TOCTOU substitution between validation and multipart upload.
func ReadAndValidateJSONLFile(path string, requirePIIScan bool) ([]byte, ValidationSummary, error) {
	f, fi, err := OpenRegularFileNonBlocking(path)
	if err != nil {
		return nil, ValidationSummary{}, fmt.Errorf("dataset %w", err)
	}
	defer func() { _ = f.Close() }()

	if fi.Size() <= 0 {
		return nil, ValidationSummary{}, fmt.Errorf("dataset %q is empty", path)
	}
	if fi.Size() > config.DefaultMaxTrainingFileBytes {
		return nil, ValidationSummary{}, fmt.Errorf("dataset %q (%d bytes) exceeds FTaaS ceiling of %d bytes",
			path, fi.Size(), config.DefaultMaxTrainingFileBytes)
	}

	data, err := io.ReadAll(io.LimitReader(f, config.DefaultMaxTrainingFileBytes+1))
	if err != nil {
		return nil, ValidationSummary{}, fmt.Errorf("read dataset %q: %w", path, err)
	}
	if len(data) == 0 {
		return nil, ValidationSummary{}, fmt.Errorf("dataset %q is empty", path)
	}
	if int64(len(data)) > config.DefaultMaxTrainingFileBytes {
		return nil, ValidationSummary{}, fmt.Errorf("dataset %q grew past FTaaS ceiling of %d bytes during read",
			path, config.DefaultMaxTrainingFileBytes)
	}

	sum, err := validateJSONLStream(bytes.NewReader(data), path, requirePIIScan)
	if err != nil {
		return nil, ValidationSummary{}, err
	}
	return data, sum, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (cr *countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	cr.n += int64(n)
	return n, err
}

func validateJSONLStream(r io.Reader, path string, requirePIIScan bool) (ValidationSummary, error) {
	hasher := sha256.New()
	limited := io.LimitReader(r, config.DefaultMaxTrainingFileBytes+1)
	cr := &countingReader{r: limited}
	tee := io.TeeReader(cr, hasher)
	scanner := bufio.NewScanner(tee)
	scanner.Buffer(make([]byte, 64*1024), MaxFeedbackRecordBytes+64*1024)

	var count int
	for scanner.Scan() {
		if cr.n > config.DefaultMaxTrainingFileBytes {
			return ValidationSummary{}, fmt.Errorf("dataset %q grew past FTaaS ceiling of %d bytes during read",
				path, config.DefaultMaxTrainingFileBytes)
		}
		// Trim only RFC 8259 JSON whitespace so non-JSON spaces (e.g. U+00A0 NBSP) fail
		// validation rather than passing locally and breaking strict JSON parsers on upload.
		line := trimJSONWhitespace(scanner.Text())
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

		prompt, completion, err := parseStrictFTaaSRecord(line)
		if err != nil {
			return ValidationSummary{}, fmt.Errorf("dataset %q line %d %w", path, count, err)
		}
		prompt = strings.TrimSpace(prompt)
		completion = strings.TrimSpace(completion)
		if err := validateFieldLengths(prompt, completion); err != nil {
			return ValidationSummary{}, fmt.Errorf("dataset %q line %d %w", path, count, err)
		}
		if requirePIIScan {
			if cat, found := ScanForPII(prompt); found {
				return ValidationSummary{}, fmt.Errorf("dataset %q line %d blocked by pre-upload PII/secret check (decoded prompt): detected %s",
					path, count, cat)
			}
			if cat, found := ScanForPII(completion); found {
				return ValidationSummary{}, fmt.Errorf("dataset %q line %d blocked by pre-upload PII/secret check (decoded completion): detected %s",
					path, count, cat)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return ValidationSummary{}, fmt.Errorf("scan dataset %q: %w", path, err)
	}
	if cr.n > config.DefaultMaxTrainingFileBytes {
		return ValidationSummary{}, fmt.Errorf("dataset %q grew past FTaaS ceiling of %d bytes during read",
			path, config.DefaultMaxTrainingFileBytes)
	}
	if cr.n == 0 || count == 0 {
		return ValidationSummary{}, fmt.Errorf("dataset %q contains 0 valid JSONL records", path)
	}

	return ValidationSummary{
		Path:        path,
		RecordCount: count,
		ByteSize:    cr.n,
		SHA256:      hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

// parseStrictFTaaSRecord decodes a normalized FTaaS JSONL object token-by-token, rejecting
// duplicate keys, unknown extra fields, non-string prompt/completion (including null),
// invalid weight values, and trailing JSON tokens so unvalidated data cannot ride into upload.
func parseStrictFTaaSRecord(line string) (string, string, error) {
	dec := json.NewDecoder(strings.NewReader(line))
	tok, err := dec.Token()
	if err != nil {
		return "", "", fmt.Errorf("invalid JSON: %w", err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return "", "", fmt.Errorf("invalid JSON: expected object")
	}

	seen := make(map[string]struct{}, 3)
	var (
		prompt     string
		completion string
		hasPrompt  bool
		hasComp    bool
	)
	for dec.More() {
		kTok, kErr := dec.Token()
		if kErr != nil {
			return "", "", fmt.Errorf("invalid JSON key: %w", kErr)
		}
		key, ok := kTok.(string)
		if !ok {
			return "", "", fmt.Errorf("invalid JSON: non-string object key")
		}
		if _, dup := seen[key]; dup {
			return "", "", fmt.Errorf("duplicate JSON key %q is prohibited", key)
		}
		seen[key] = struct{}{}

		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return "", "", fmt.Errorf("invalid JSON value for %q: %w", key, err)
		}
		switch key {
		case "prompt":
			if len(raw) == 0 || raw[0] != '"' {
				return "", "", fmt.Errorf("prompt must be a JSON string")
			}
			if err := json.Unmarshal(raw, &prompt); err != nil {
				return "", "", fmt.Errorf("prompt must be a JSON string: %w", err)
			}
			hasPrompt = true
		case "completion":
			if len(raw) == 0 || raw[0] != '"' {
				return "", "", fmt.Errorf("completion must be a JSON string")
			}
			if err := json.Unmarshal(raw, &completion); err != nil {
				return "", "", fmt.Errorf("completion must be a JSON string: %w", err)
			}
			hasComp = true
		case "weight":
			if strings.TrimSpace(string(raw)) != "null" {
				var w float64
				if err := json.Unmarshal(raw, &w); err != nil || math.IsNaN(w) || math.IsInf(w, 0) || w <= 0 {
					return "", "", fmt.Errorf("has invalid weight")
				}
			}
		default:
			return "", "", fmt.Errorf("contains unexpected field %q (only prompt, completion, and optional weight are permitted)", key)
		}
	}

	endTok, err := dec.Token()
	if err != nil {
		return "", "", fmt.Errorf("invalid JSON object closing: %w", err)
	}
	if delim, ok := endTok.(json.Delim); !ok || delim != '}' {
		return "", "", fmt.Errorf("invalid JSON: expected closing brace")
	}
	if _, trailingErr := dec.Token(); !errors.Is(trailingErr, io.EOF) {
		return "", "", fmt.Errorf("invalid JSON: trailing data after object")
	}
	if !hasPrompt || !hasComp {
		return "", "", fmt.Errorf("missing required prompt/completion fields")
	}
	return prompt, completion, nil
}

func trimJSONWhitespace(s string) string {
	return strings.Trim(s, " \t\r\n")
}

func (s *Store) isExistingCuratedQueue(outPath string) bool {
	if strings.TrimSpace(s.dir) == "" {
		return false
	}
	dirCanon := canonicalPathForCompare(s.dir)
	outParentCanon := canonicalPathForCompare(filepath.Dir(outPath))
	if dirCanon != outParentCanon {
		return false
	}
	if !isSentinelFeedbackFilename(filepath.Base(outPath)) {
		return false
	}
	return isExistingCuratedQueueFile(outPath)
}

func isExistingCuratedQueueFile(outPath string) bool {
	f, _, err := OpenRegularFileNonBlocking(outPath)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(io.LimitReader(f, MaxFeedbackRecordBytes+64*1024))
	sc.Buffer(make([]byte, 32*1024), MaxFeedbackRecordBytes+64*1024)
	for sc.Scan() {
		line := trimJSONWhitespace(sc.Text())
		if line == "" {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			return false
		}
		if _, hasLabel := obj["label"]; hasLabel {
			return true
		}
		if _, hasReviewed := obj["reviewed_at"]; hasReviewed {
			return true
		}
		if _, hasRedacted := obj["redacted"]; hasRedacted {
			return true
		}
		return false
	}
	return false
}

func validateFieldLengths(prompt, completion string) error {
	pLen := utf8.RuneCountInString(prompt)
	cLen := utf8.RuneCountInString(completion)
	if pLen < MinPromptChars || cLen < 1 {
		return fmt.Errorf("has empty or overly short prompt/completion")
	}
	if pLen > MaxFieldChars || cLen > MaxFieldChars {
		return fmt.Errorf("exceeds FTaaS %d-character per-field limit", MaxFieldChars)
	}
	return nil
}

func sameTargetPath(a, b string) bool {
	if fiA, errA := os.Stat(a); errA == nil {
		if fiB, errB := os.Stat(b); errB == nil && os.SameFile(fiA, fiB) {
			return true
		}
	}
	return canonicalPathForCompare(a) == canonicalPathForCompare(b)
}

func canonicalPathForCompare(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = filepath.Clean(p)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved)
	}
	dir := filepath.Dir(abs)
	if resolvedDir, err := filepath.EvalSymlinks(dir); err == nil {
		return filepath.Clean(filepath.Join(resolvedDir, filepath.Base(abs)))
	}
	return filepath.Clean(abs)
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
	scanner.Buffer(make([]byte, 64*1024), MaxFeedbackRecordBytes+64*1024)
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
		if len(payload) > MaxFeedbackRecordBytes {
			return ExportSummary{}, fmt.Errorf("serialized feedback record (%d bytes) exceeds per-row limit of %d bytes", len(payload), MaxFeedbackRecordBytes)
		}
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
