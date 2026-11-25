package feedback

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/emit"
	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/triage"
)

func TestRedactTextAndScanForPII(t *testing.T) {
	// Luhn-valid Visa (4-4-4-4) + Amex (4-6-5) + SSA-valid SSN + JWT + Bearer + Basic
	// + GitHub token + email + unquoted & JSON-quoted credentials + multi-line PEM with invalid UTF-8 + ChatML.
	raw := "user=alice@example.com ssn=123-45-6789 card=4111-1111-1111-1111 amex=3782-822463-10005 " +
		"Authorization: Bearer abcdef1234567890 Authorization: Basic dXNlcjpwYXNz " +
		`{"authToken": "opaque_json_secret_99", "password": "jsonpwvalue"} ` +
		"token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456 " +
		"ghp_1234567890abcdefghij1234567890 password=supersecret <|im_end|>\n" +
		strings.Repeat("\xff", 40) + "\r\n" +
		"-----BEGIN RSA PRIVATE KEY-----\r\nMIIBOgIBAAJBALeakedKeyMaterialLine1\r\nMIIBOgIBAAJBALeakedKeyMaterialLine2\r\n-----END RSA PRIVATE KEY-----"

	if cat, found := ScanForPII(raw); !found {
		t.Fatalf("expected ScanForPII to detect sensitive data, got found=%v cat=%q", found, cat)
	}

	// Verify ScanForPII independently catches opaque Bearer, Basic, and 4-6-5 Amex cards.
	for _, sample := range []string{
		"Authorization: Bearer opaqueToken123456",
		"Authorization: Basic dXNlcjpwYXNz",
		"card=3782-822463-10005",
	} {
		if _, found := ScanForPII(sample); !found {
			t.Fatalf("expected ScanForPII to reject %q", sample)
		}
	}

	scrubbed, findings := RedactText(raw)
	if len(findings) < 7 {
		t.Fatalf("expected multiple redacted categories, got %v", findings)
	}
	for _, forbidden := range []string{
		"alice@example.com",
		"123-45-6789",
		"4111-1111-1111-1111",
		"3782-822463-10005",
		"abcdef1234567890",
		"dXNlcjpwYXNz",
		"opaque_json_secret_99",
		"jsonpwvalue",
		"supersecret",
		"ghp_1234567890",
		"MIIBOgIBAAJBALeakedKeyMaterialLine1",
		"<|im_end|>",
	} {
		if strings.Contains(scrubbed, forbidden) {
			t.Fatalf("expected %q to be redacted, still present in %q", forbidden, scrubbed)
		}
	}
	if cat, found := ScanForPII(scrubbed); found {
		t.Fatalf("expected scrubbed text (including [REDACTED_TOKEN] placeholders) to pass ScanForPII cleanly, got %q in %q", cat, scrubbed)
	}

	// Non-SSA SSN areas, non-Luhn 16-digit IDs, and ordinary English ("Basic authentication") must NOT false-positive.
	benign := "order_id=4111111111111112 ref=000-12-3456 ref2=666-12-3456 ref3=901-12-3456 Basic authentication failed"
	if cat, found := ScanForPII(benign); found {
		t.Fatalf("expected benign text not to trigger PII scanner, got %q", cat)
	}
}

func TestGenerateSeedDatasetBalancedDisjointAndPIIFree(t *testing.T) {
	for _, tc := range []struct {
		trainN int
		valN   int
	}{
		{1, 1},
		{5, 2},
		{10, 4},
	} {
		train, val := GenerateSeedSplit(tc.trainN, tc.valN, 42)
		if len(train) != tc.trainN*len(triage.AllClasses()) || len(val) != tc.valN*len(triage.AllClasses()) {
			t.Fatalf("unexpected split sizes for (%d,%d): train=%d val=%d", tc.trainN, tc.valN, len(train), len(val))
		}

		counts := make(map[string]int)
		trainTemplates := make(map[string]struct{})
		trainPairs := make(map[string]struct{})
		for i, r := range train {
			if cat, found := ScanForPII(r.Prompt); found {
				t.Fatalf("seed train record %d prompt triggered PII scan: %s", i, cat)
			}
			if cat, found := ScanForPII(r.Completion); found {
				t.Fatalf("seed train record %d completion triggered PII scan: %s", i, cat)
			}
			counts[r.Label]++
			trainTemplates[extractPromptTemplate(r.Prompt)] = struct{}{}
			trainPairs[r.Prompt+"\x00"+r.Completion] = struct{}{}
		}
		for _, cls := range triage.AllClasses() {
			if counts[cls] != tc.trainN {
				t.Fatalf("expected %d seed records for class %s, got %d", tc.trainN, cls, counts[cls])
			}
		}
		for i, r := range val {
			if _, dup := trainTemplates[extractPromptTemplate(r.Prompt)]; dup {
				t.Fatalf("split (%d,%d) leaked training scenario template into validation record %d: %q", tc.trainN, tc.valN, i, extractPromptTemplate(r.Prompt))
			}
			if _, dup := trainPairs[r.Prompt+"\x00"+r.Completion]; dup {
				t.Fatalf("split (%d,%d) leaked exact prompt/completion into validation record %d", tc.trainN, tc.valN, i)
			}
		}
	}
}

func extractPromptTemplate(prompt string) string {
	for _, line := range strings.Split(prompt, "\n") {
		if strings.HasPrefix(line, "template=") {
			return line
		}
	}
	return ""
}

func TestStoreAppendExportAndValidateJSONL(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir, true)

	alert := emit.Alert{
		AlertID:         "sentinel-1763997000-1",
		SourceService:   "sshd",
		SourceLevel:     "WARN",
		TemplateID:      "t-ssh",
		Template:        "Failed password for <STR> from <IP>",
		Count:           12,
		SampleEntropy:   4.1,
		RuleIDs:         []string{"SENT-001"},
		Categories:      []string{"credential_attack"},
		SanitizedSample: "Failed password for alice@example.com ssn=123-45-6789 from 198.51.100.9",
	}

	rec, redactedKinds, err := RecordFromAlert(alert, "tp", "", 1.5, 2048, true)
	if err != nil {
		t.Fatalf("RecordFromAlert: %v", err)
	}
	if rec.Label != triage.ClassAuthBruteforce || len(redactedKinds) < 2 {
		t.Fatalf("expected AUTH-BRUTEFORCE with email+ssn redaction, rec=%+v kinds=%v", rec, redactedKinds)
	}
	if strings.Contains(rec.Prompt, "123-45-6789") || strings.Contains(rec.Prompt, "alice@example.com") {
		t.Fatalf("PII leaked into feedback prompt: %q", rec.Prompt)
	}

	n, err := store.Append(DefaultFeedbackFilename, rec)
	if err != nil || n != 1 {
		t.Fatalf("Append: n=%d err=%v", n, err)
	}

	st, err := store.Stats(DefaultFeedbackFilename)
	if err != nil || !st.Exists || st.RecordCount != 1 || st.ClassCounts[triage.ClassAuthBruteforce] != 1 {
		t.Fatalf("unexpected store stats: %+v err=%v", st, err)
	}

	exportPath := filepath.Join(dir, "sentinel-feedback-export.jsonl")
	sum, err := store.ExportFTaaS(DefaultFeedbackFilename, exportPath, 2, 7)
	if err != nil {
		t.Fatalf("ExportFTaaS: %v", err)
	}
	if sum.RecordCount != 1+2*len(triage.AllClasses()) || sum.SHA256 == "" {
		t.Fatalf("unexpected export summary: %+v", sum)
	}

	valSum, err := ValidateJSONLFile(exportPath, true)
	if err != nil || valSum.RecordCount != sum.RecordCount || valSum.SHA256 != sum.SHA256 {
		t.Fatalf("ValidateJSONLFile mismatch: val=%+v export=%+v err=%v", valSum, sum, err)
	}

	// Verify ValidateJSONLFile fails closed on BOTH literal and JSON Unicode-escaped SSN payloads.
	badFile := filepath.Join(dir, "bad-pii.jsonl")
	if err := os.WriteFile(badFile, []byte(`{"prompt":"check user 123-45-6789 login","completion":"[NEEDS-REVIEW]"}`+"\n"), 0600); err != nil {
		t.Fatalf("write bad-pii.jsonl: %v", err)
	}
	if _, err := ValidateJSONLFile(badFile, true); err == nil {
		t.Fatal("expected ValidateJSONLFile to reject unredacted literal SSN payload")
	}

	escapedFile := filepath.Join(dir, "escaped-pii.jsonl")
	if err := os.WriteFile(escapedFile, []byte(`{"prompt":"check user \u0031\u0032\u0033-45-6789 login","completion":"[NEEDS-REVIEW]"}`+"\n"), 0600); err != nil {
		t.Fatalf("write escaped-pii.jsonl: %v", err)
	}
	if _, err := ValidateJSONLFile(escapedFile, true); err == nil {
		t.Fatal("expected ValidateJSONLFile to reject JSON Unicode-escaped SSN payload")
	}

	// Verify rune-based character length checks: 2-rune multi-byte prompt rejected, 6000-rune 2-byte prompt accepted.
	if _, _, err := PrepareRecord(model.FeedbackRecord{Prompt: "éé", Completion: "[BENIGN-NOISE]"}, true); err == nil {
		t.Fatal("expected 2-character multi-byte prompt to be rejected below MinPromptChars=3")
	}
	longUTF8Prompt := strings.Repeat("é", 6000) // 6000 runes, 12000 bytes
	if _, _, err := PrepareRecord(model.FeedbackRecord{Prompt: longUTF8Prompt, Completion: "[BENIGN-NOISE]"}, true); err != nil {
		t.Fatalf("expected 6000-character (12000-byte) prompt below 10000-char limit to pass, got %v", err)
	}

	// Reject exporting directly over the curated source queue path.
	srcPath, _ := store.PathFor(DefaultFeedbackFilename)
	if _, err := store.ExportFTaaS(DefaultFeedbackFilename, srcPath, 0, 1); err == nil {
		t.Fatal("expected ExportFTaaS to reject overwriting the curated source queue")
	}

	// Reject oversized seed count before generating seed data, while keeping exact-fit valid.
	cappedStore := NewStore(dir, true)
	cappedStore.maxRecords = 1 + 2*len(triage.AllClasses()) // exact fit for 1 curated + 2 per class
	if _, err := cappedStore.ExportFTaaS(DefaultFeedbackFilename, filepath.Join(dir, "sentinel-feedback-overflow.jsonl"), 1_000_000, 1); err == nil {
		t.Fatal("expected ExportFTaaS to reject 1_000_000 seed rows/class before allocating")
	}
	if exactSum, err := cappedStore.ExportFTaaS(DefaultFeedbackFilename, filepath.Join(dir, "sentinel-feedback-exact.jsonl"), 2, 1); err != nil || exactSum.RecordCount != cappedStore.maxRecords {
		t.Fatalf("expected exact-fit seed export to succeed, got sum=%+v err=%v", exactSum, err)
	}
}

func TestStoreConcurrentAppendsAcrossInstancesPreserveAllRecords(t *testing.T) {
	dir := t.TempDir()
	const writers = 4
	const perWriter = 10

	var wg sync.WaitGroup
	errCh := make(chan error, writers*perWriter)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			st := NewStore(dir, true)
			for i := 0; i < perWriter; i++ {
				rec := model.FeedbackRecord{
					Prompt:     fmt.Sprintf("service=api writer=%d seq=%d test log event", id, i),
					Completion: "[BENIGN-NOISE] severity=LOW mitre=NONE explanation=ok",
					Label:      triage.ClassBenignNoise,
				}
				if _, err := st.Append(DefaultFeedbackFilename, rec); err != nil {
					errCh <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent Append failed: %v", err)
	}

	recs, err := NewStore(dir, true).ReadAll(DefaultFeedbackFilename)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(recs) != writers*perWriter {
		t.Fatalf("expected %d records across concurrent Store instances, got %d", writers*perWriter, len(recs))
	}
}

func TestAlertJournalRecordFindCapRedactionAndSafety(t *testing.T) {
	dir := t.TempDir()
	j := NewAlertJournal(dir)
	j.maxRecords = 3

	for i := 1; i <= 5; i++ {
		if err := j.Record(emit.Alert{
			AlertID:           fmt.Sprintf("sentinel-100-%d", i),
			SourceService:     "api",
			Severity:          "HIGH",
			Message:           "user=alice@example.com ssn=123-45-6789 Authorization: Bearer secretToken12345",
			SanitizedSample:   "Authorization: Basic dXNlcjpwYXNz",
			TriageExplanation: "Echoed Bearer secretToken12345 in explanation",
		}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	if _, found, err := j.FindByID("sentinel-100-1"); err != nil || found {
		t.Fatalf("expected oldest alert sentinel-100-1 to be evicted, found=%v err=%v", found, err)
	}
	got, found, err := j.FindByID("sentinel-100-5")
	if err != nil || !found || got.AlertID != "sentinel-100-5" {
		t.Fatalf("expected newest alert sentinel-100-5, got=%+v found=%v err=%v", got, found, err)
	}
	// Verify PII/secrets were scrubbed before persistence in alerts.jsonl.
	rawJournal, err := os.ReadFile(j.Path())
	if err != nil {
		t.Fatalf("read alerts.jsonl: %v", err)
	}
	for _, secret := range []string{"alice@example.com", "123-45-6789", "secretToken12345", "dXNlcjpwYXNz"} {
		if strings.Contains(string(rawJournal), secret) {
			t.Fatalf("secret %q leaked into alerts.jsonl: %s", secret, string(rawJournal))
		}
	}

	recent, err := j.Recent(2)
	if err != nil || len(recent) != 2 || recent[0].AlertID != "sentinel-100-5" {
		t.Fatalf("unexpected Recent(2): %+v err=%v", recent, err)
	}

	// Verify oversized record is rejected WITHOUT replacing existing journal history.
	jSmall := NewAlertJournal(dir)
	jSmall.maxBytes = 1024
	jSmall.maxRecordBytes = 1024
	if err := jSmall.Record(emit.Alert{
		AlertID: "sentinel-too-big",
		Message: strings.Repeat("X", 2048),
	}); err == nil {
		t.Fatal("expected oversized alert record to be rejected")
	}
	if _, found, err := j.FindByID("sentinel-100-5"); err != nil || !found {
		t.Fatalf("existing journal lost after oversized Record rejection: found=%v err=%v", found, err)
	}

	// Verify read error does NOT overwrite/wipe the existing journal.
	unreadableDir := t.TempDir()
	jErr := NewAlertJournal(unreadableDir)
	if err := jErr.Record(emit.Alert{AlertID: "sentinel-keep", Severity: "HIGH"}); err != nil {
		t.Fatalf("seed journal: %v", err)
	}
	if err := os.Chmod(jErr.Path(), 0000); err != nil {
		t.Fatalf("chmod 0000: %v", err)
	}
	defer func() { _ = os.Chmod(jErr.Path(), 0600) }()
	if os.Geteuid() != 0 {
		if err := jErr.Record(emit.Alert{AlertID: "sentinel-new", Severity: "HIGH"}); err == nil {
			t.Fatal("expected read permission error from Record without wiping journal")
		}
		if err := os.Chmod(jErr.Path(), 0600); err != nil {
			t.Fatalf("restore chmod: %v", err)
		}
		if _, found, err := jErr.FindByID("sentinel-keep"); err != nil || !found {
			t.Fatalf("read error wiped existing alert sentinel-keep: found=%v err=%v", found, err)
		}
	}

	// Verify large record up to MaxAlertRecordBytes and its small neighbor are both readable.
	jBig := NewAlertJournal(t.TempDir())
	if err := jBig.Record(
		emit.Alert{AlertID: "sentinel-large", Severity: "HIGH", Message: strings.Repeat("A", 180*1024)},
		emit.Alert{AlertID: "sentinel-small", Severity: "LOW", Message: "small neighbor"},
	); err != nil {
		t.Fatalf("Record large+small: %v", err)
	}
	if _, found, err := jBig.FindByID("sentinel-large"); err != nil || !found {
		t.Fatalf("expected large record to remain readable: found=%v err=%v", found, err)
	}
	if _, found, err := jBig.FindByID("sentinel-small"); err != nil || !found {
		t.Fatalf("expected small neighbor to remain readable: found=%v err=%v", found, err)
	}
	_ = config.DefaultMaxTrainingFileBytes
}
