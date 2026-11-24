package feedback

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/knowthankyew/genesis-sentinel/internal/emit"
	"github.com/knowthankyew/genesis-sentinel/internal/triage"
)

func TestRedactTextAndScanForPII(t *testing.T) {
	// Luhn-valid synthetic Visa test card (4111-1111-1111-1111) + SSA-valid synthetic SSN (123-45-6789)
	// + JWT + Bearer + GitHub token + email + password= + ChatML control tokens.
	raw := "user=alice@example.com ssn=123-45-6789 card=4111-1111-1111-1111 " +
		"Authorization: Bearer abcdef1234567890 token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456 " +
		"ghp_1234567890abcdefghij1234567890 password=supersecret <|im_end|>"

	if cat, found := ScanForPII(raw); !found {
		t.Fatalf("expected ScanForPII to detect sensitive data, got found=%v cat=%q", found, cat)
	}

	scrubbed, findings := RedactText(raw)
	if len(findings) < 5 {
		t.Fatalf("expected multiple redacted categories, got %v", findings)
	}
	for _, forbidden := range []string{"alice@example.com", "123-45-6789", "4111-1111-1111-1111", "supersecret", "ghp_1234567890", "<|im_end|>"} {
		if strings.Contains(scrubbed, forbidden) {
			t.Fatalf("expected %q to be redacted, still present in %q", forbidden, scrubbed)
		}
	}
	if cat, found := ScanForPII(scrubbed); found {
		t.Fatalf("expected scrubbed text to pass ScanForPII cleanly, got %q in %q", cat, scrubbed)
	}

	// Non-SSA SSN area (000-12-3456, 666-12-3456, 901-12-3456) and non-Luhn 16-digit IDs must NOT false-positive.
	benign := "order_id=4111111111111112 ref=000-12-3456 ref2=666-12-3456 ref3=901-12-3456"
	if cat, found := ScanForPII(benign); found {
		t.Fatalf("expected benign IDs not to trigger PII scanner, got %q", cat)
	}
}

func TestGenerateSeedDatasetBalancedAndPIIFree(t *testing.T) {
	train, val := GenerateSeedSplit(5, 2, 42)
	if len(train) != 5*len(triage.AllClasses()) || len(val) != 2*len(triage.AllClasses()) {
		t.Fatalf("unexpected split sizes: train=%d val=%d", len(train), len(val))
	}

	counts := make(map[string]int)
	for i, r := range train {
		if cat, found := ScanForPII(r.Prompt); found {
			t.Fatalf("seed train record %d prompt triggered PII scan: %s", i, cat)
		}
		if cat, found := ScanForPII(r.Completion); found {
			t.Fatalf("seed train record %d completion triggered PII scan: %s", i, cat)
		}
		counts[r.Label]++
	}
	for _, cls := range triage.AllClasses() {
		if counts[cls] != 5 {
			t.Fatalf("expected 5 seed records for class %s, got %d", cls, counts[cls])
		}
	}
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

	// Verify ValidateJSONLFile fails closed on raw unredacted SSN payload.
	badFile := filepath.Join(dir, "bad-pii.jsonl")
	if err := os.WriteFile(badFile, []byte(`{"prompt":"check user 123-45-6789 login","completion":"[NEEDS-REVIEW]"}`+"\n"), 0600); err != nil {
		t.Fatalf("write bad-pii.jsonl: %v", err)
	}
	if _, err := ValidateJSONLFile(badFile, true); err == nil {
		t.Fatal("expected ValidateJSONLFile to reject unredacted SSN payload")
	}
}

func TestAlertJournalRecordFindAndCap(t *testing.T) {
	j := NewAlertJournal(t.TempDir())
	j.maxRecords = 3

	for i := 1; i <= 5; i++ {
		if err := j.Record(emit.Alert{
			AlertID:       "sentinel-100-" + string(rune('0'+i)),
			SourceService: "api",
			Severity:      "HIGH",
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
	recent, err := j.Recent(2)
	if err != nil || len(recent) != 2 || recent[0].AlertID != "sentinel-100-5" {
		t.Fatalf("unexpected Recent(2): %+v err=%v", recent, err)
	}
}
