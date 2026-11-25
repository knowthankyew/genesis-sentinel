package feedback

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/emit"
	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/triage"
)

func TestRedactTextAndScanForPII(t *testing.T) {
	// Luhn-valid Visa (4-4-4-4) + Amex (4-6-5) + SSA-valid SSN + JWT + Bearer + Basic
	// + GitHub token + email + unquoted & JSON-quoted credentials + multi-line PEM with invalid UTF-8 + ChatML.
	raw := "user=alice@example.com ssn=123-45-6789 card=4111-1111-1111-1111 amex=3782-822463-10005 " +
		`Authorization: Bearer abcdef1234567890 Authorization: Basic dXNlcjpwYXNz {"Authorization": "Basic YTpi"} ` +
		`{"authToken": "opaque_json_secret_99", "password": "before\"after_escaped_quote"} ` +
		`DOCKER_AUTH_CONFIG={"auths":{"reg.local":{"auth":"cmVnOnNlY3JldA=="}}} ` +
		"token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456 " +
		"ghp_1234567890abcdefghij1234567890 password=supersecret <|im_end|>\n" +
		strings.Repeat("\xff", 40) + "\r\n" +
		"-----BEGIN RSA PRIVATE KEY-----\r\nMIIBOgIBAAJBALeakedKeyMaterialLine1\r\nMIIBOgIBAAJBALeakedKeyMaterialLine2\r\n-----END RSA PRIVATE KEY-----"

	if cat, found := ScanForPII(raw); !found {
		t.Fatalf("expected ScanForPII to detect sensitive data, got found=%v cat=%q", found, cat)
	}

	// Verify ScanForPII independently catches Bearer, Basic (including short standalone Basic YTpi),
	// quoted Authorization, multi-line DOCKER_AUTH_CONFIG, partial [REDACTED_SECRET] bypass,
	// boundary card ("4111 1111 1111 1111 2 attempts"), credential assignments, emails, and 4-6-5 Amex cards.
	for _, sample := range []string{
		"Authorization: Bearer opaqueToken123456",
		"Authorization: Bearer abc",
		"Authorization: Basic dXNlcjpwYXNz",
		"Basic YTpi",
		"Basic YTo/",
		"Basic YTo+",
		"Basic dGVzdDoxMjPCow==",
		"Basic YTqj",
		`{"Authorization": "Basic YTpi"}`,
		`{"token": "opaque_tok_value_99"}`,
		`DOCKER_AUTH_CONFIG={"auths":{"reg.local":{"auth":"cmVnOnNlY3JldA=="}}}`,
		"DOCKER_AUTH_CONFIG={\n  \"auths\": {\n    \"reg.local\": {\"auth\": \"cmVnOnNlY3JldA==\"}\n  }\n}",
		`DOCKER_AUTH_CONFIG={"padding":"` + strings.Repeat("A", 17000) + `","auth":"c2VjcmV0"}`,
		`DOCKER_AUTH_CONFIG={"padding":"` + strings.Repeat("B", 17000) + `","auth":"c2VjcmV0"`,
		`password=myplaintextpw`,
		`password=[REDACTED_SECRET]leaked_suffix`,
		`{"password":"[REDACTED_SECRET]leaked_suffix"}`,
		`contact alice@example.com`,
		"card=3782-822463-10005",
		"card=4111 1111 1111 1111 2 attempts",
		"batch 1234 4111 1111 1111 1111",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig1234567890",
		"postgres://admin:p@ssword@db.internal:5432/app",
		"postgres://admin:p;a,ss@db.internal:5432/app",
		"postgres://admin:p'a)ss@db.internal:5432/app",
		`password="unterminated_secret_val`,
		`DB_PASSWORD="part1"'part2' nextarg`,
		"-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBALeakedTruncatedKey",
	} {
		if _, found := ScanForPII(sample); !found {
			t.Fatalf("expected ScanForPII to reject %q", sample)
		}
	}

	// Verify boundary card redaction, sliding-window card following another number,
	// connection URL credentials (with '@', ';', ',' inside password), short-claims JWT,
	// prefixed keys (DB_PASSWORD), adjacent quoted sections, unterminated quotes, and truncated PEM blocks.
	cardBoundary, _ := RedactText("card=4111 1111 1111 1111 2 attempts")
	if cardBoundary != "card=[REDACTED_CARD] 2 attempts" {
		t.Fatalf("unexpected card boundary redaction: got %q", cardBoundary)
	}
	cardSlide, _ := RedactText("batch 1234 4111 1111 1111 1111")
	if cardSlide != "batch 1234 [REDACTED_CARD]" {
		t.Fatalf("unexpected sliding card redaction: got %q", cardSlide)
	}
	urlCred, _ := RedactText("connect postgres://admin:p;a,ss@db.internal:5432/app, next")
	if strings.Contains(urlCred, "p;a,ss") || strings.Contains(urlCred, "admin:") || !strings.Contains(urlCred, "postgres://[REDACTED_SECRET]@db.internal:5432/app, next") {
		t.Fatalf("unexpected URL credential redaction: got %q", urlCred)
	}
	if cat, found := ScanForPII(urlCred); found {
		t.Fatalf("scrubbed URL credential failed re-scan (%s): %q", cat, urlCred)
	}
	adjCred, _ := RedactText(`DB_PASSWORD="part1"'part2' nextarg=keep`)
	if strings.Contains(adjCred, "part1") || strings.Contains(adjCred, "part2") || !strings.Contains(adjCred, "nextarg=keep") {
		t.Fatalf("unexpected prefixed/adjacent quoted credential redaction: got %q", adjCred)
	}
	if cat, found := ScanForPII(adjCred); found {
		t.Fatalf("scrubbed prefixed credential failed re-scan (%s): %q", cat, adjCred)
	}
	shortJWT, _ := RedactText("tok eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.sig1234567890")
	if strings.Contains(shortJWT, "sig1234567890") {
		t.Fatalf("short-claims JWT survived RedactText: %q", shortJWT)
	}
	untermCred, _ := RedactText(`password="unterminated_secret_val`)
	if strings.Contains(untermCred, "unterminated_secret_val") {
		t.Fatalf("unterminated quoted credential survived RedactText: %q", untermCred)
	}
	truncPEM, _ := RedactText("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBALeakedTruncatedKey")
	if strings.Contains(truncPEM, "MIIBOgIBAAJBALeakedTruncatedKey") {
		t.Fatalf("truncated PEM private key survived RedactText: %q", truncPEM)
	}
	// Verify oversized complete and unterminated DOCKER_AUTH_CONFIG objects (>16 KiB) never leak trailing auth fields.
	for _, bigCfg := range []string{
		`DOCKER_AUTH_CONFIG={"padding":"` + strings.Repeat("A", 17000) + `","auth":"c2VjcmV0"}`,
		`DOCKER_AUTH_CONFIG={"padding":"` + strings.Repeat("B", 17000) + `","auth":"c2VjcmV0"`,
	} {
		redBig, _ := RedactText(bigCfg)
		if strings.Contains(redBig, "c2VjcmV0") || strings.Contains(redBig, `"auth"`) {
			t.Fatalf("oversized DOCKER_AUTH_CONFIG leaked trailing auth field: %q", redBig)
		}
	}
	// Verify Basic tokens ending in '/' or '+' plus UTF-8 & Latin-1 RFC 7617 credentials and token KV assignments are scrubbed.
	basicEdge, _ := RedactText(`Basic YTo/ Basic YTo+ Basic dGVzdDoxMjPCow== Basic YTqj {"token":"opaque_tok_value_99"}`)
	for _, tok := range []string{"YTo/", "YTo+", "dGVzdDoxMjPCow==", "YTqj", "opaque_tok_value_99"} {
		if strings.Contains(basicEdge, tok) {
			t.Fatalf("sensitive token %q survived RedactText: %q", tok, basicEdge)
		}
	}
	if cat, found := ScanForPII(basicEdge); found {
		t.Fatalf("re-scan of scrubbed basicEdge flagged %q in %q", cat, basicEdge)
	}
	mlDocker, _ := RedactText("DOCKER_AUTH_CONFIG={\n  \"auths\": {\"reg\": {\"auth\": \"cmVnOnNlY3JldA==\"}}\n}")
	if strings.Contains(mlDocker, "cmVnOnNlY3JldA==") || strings.Contains(mlDocker, "auths") {
		t.Fatalf("multi-line DOCKER_AUTH_CONFIG leaked: %q", mlDocker)
	}
	partialBypass, _ := RedactText(`password=[REDACTED_SECRET]leaked_suffix {"password":"[REDACTED_SECRET]leaked_suffix"}`)
	if strings.Contains(partialBypass, "leaked_suffix") {
		t.Fatalf("partial redaction marker bypass survived: %q", partialBypass)
	}
	if cat, found := ScanForPII(partialBypass); found {
		t.Fatalf("expected cleanly re-scrubbed output to pass ScanForPII, got %q in %q", cat, partialBypass)
	}

	scrubbed, findings := RedactText(raw)
	if len(findings) < 8 {
		t.Fatalf("expected multiple redacted categories, got %v", findings)
	}
	for _, forbidden := range []string{
		"alice@example.com",
		"123-45-6789",
		"4111-1111-1111-1111",
		"3782-822463-10005",
		"abcdef1234567890",
		"dXNlcjpwYXNz",
		"YTpi",
		"opaque_json_secret_99",
		"before",
		"after_escaped_quote",
		"cmVnOnNlY3JldA==",
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

	// Non-SSA SSN areas, non-Luhn 16-digit IDs, and ordinary English ("Basic authentication" / "Basic Authentication") must NOT false-positive.
	benign := "order_id=4111111111111112 ref=000-12-3456 ref2=666-12-3456 ref3=901-12-3456 Basic authentication failed; Basic Authentication failed"
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
		valCounts := make(map[string]int)
		for i, r := range val {
			if cat, found := ScanForPII(r.Prompt); found {
				t.Fatalf("seed val record %d prompt triggered PII scan: %s", i, cat)
			}
			if cat, found := ScanForPII(r.Completion); found {
				t.Fatalf("seed val record %d completion triggered PII scan: %s", i, cat)
			}
			valCounts[r.Label]++
			if _, dup := trainTemplates[extractPromptTemplate(r.Prompt)]; dup {
				t.Fatalf("split (%d,%d) leaked training scenario template into validation record %d: %q", tc.trainN, tc.valN, i, extractPromptTemplate(r.Prompt))
			}
			if _, dup := trainPairs[r.Prompt+"\x00"+r.Completion]; dup {
				t.Fatalf("split (%d,%d) leaked exact prompt/completion into validation record %d", tc.trainN, tc.valN, i)
			}
		}
		for _, cls := range triage.AllClasses() {
			if valCounts[cls] != tc.valN {
				t.Fatalf("expected %d val records for class %s, got %d", tc.valN, cls, valCounts[cls])
			}
		}
	}

	// Verify deterministic seed generation produces identical records across all rows.
	a := GenerateSeedDataset(2, 99)
	b := GenerateSeedDataset(2, 99)
	if len(a) == 0 || len(a) != len(b) {
		t.Fatalf("GenerateSeedDataset unexpected lengths: len(a)=%d len(b)=%d", len(a), len(b))
	}
	for i := range a {
		if a[i].Prompt != b[i].Prompt || a[i].Completion != b[i].Completion || a[i].Label != b[i].Label || !a[i].ReviewedAt.Equal(b[i].ReviewedAt) {
			t.Fatalf("GenerateSeedDataset diverged at record %d: a=%+v b=%+v", i, a[i], b[i])
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

	// Verify writer-to-validator round-trip accepts Sentinel-generated quoted placeholders
	// (serialized as password=\"[REDACTED_SECRET]\") while still rejecting real quoted credentials.
	quotedPlaceholderPath := filepath.Join(dir, "quoted-placeholder.jsonl")
	if _, err := WriteFTaaSDataset(quotedPlaceholderPath, []model.FeedbackRecord{{
		Prompt:     `login attempt password="real_plaintext_secret" failed`,
		Completion: "[AUTH-BRUTEFORCE] severity=HIGH mitre=TA0006 explanation=ok",
		Label:      triage.ClassAuthBruteforce,
	}}, true); err != nil {
		t.Fatalf("WriteFTaaSDataset quoted placeholder: %v", err)
	}
	if _, err := ValidateJSONLFile(quotedPlaceholderPath, true); err != nil {
		t.Fatalf("ValidateJSONLFile rejected Sentinel-generated quoted [REDACTED_SECRET] placeholder: %v", err)
	}
	rawQuotedCred := filepath.Join(dir, "raw-quoted-cred.jsonl")
	if err := os.WriteFile(rawQuotedCred, []byte(`{"prompt":"login attempt password=\"real_plaintext_secret\" failed","completion":"[AUTH-BRUTEFORCE]"}`+"\n"), 0600); err != nil {
		t.Fatalf("write raw-quoted-cred.jsonl: %v", err)
	}
	if _, err := ValidateJSONLFile(rawQuotedCred, true); err == nil {
		t.Fatal("expected ValidateJSONLFile to reject unredacted JSON-escaped quoted credential")
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

	// Verify ValidateJSONLFile rejects schema violations using PII-free fixtures (extra field,
	// duplicate keys, null prompt, non-JSON NBSP whitespace) plus email & credential KV PII.
	for name, content := range map[string]string{
		"extra-field.jsonl":  `{"prompt":"valid prompt text","completion":"[BENIGN-NOISE]","extra":"harmless metadata"}` + "\n",
		"dup-key.jsonl":      `{"prompt":"first clean prompt","prompt":"second clean prompt","completion":"[BENIGN-NOISE]"}` + "\n",
		"null-prompt.jsonl":  `{"prompt":null,"completion":"[BENIGN-NOISE]"}` + "\n",
		"null-weight.jsonl":  `{"prompt":"valid prompt text","completion":"[BENIGN-NOISE]","weight":null}` + "\n",
		"padded-10001.jsonl": `{"prompt":"` + strings.Repeat(" ", 10001) + `abc","completion":"[BENIGN-NOISE]"}` + "\n",
		"nbsp-prefix.jsonl":  "\u00a0" + `{"prompt":"valid prompt text","completion":"[BENIGN-NOISE]"}` + "\n",
		"invalid-utf8.jsonl": "{\"prompt\":\"bad \xff utf8\",\"completion\":\"[BENIGN-NOISE]\"}\n",
		"email-pii.jsonl":    `{"prompt":"contact alice@example.com for alert","completion":"[BENIGN-NOISE]"}` + "\n",
		"cred-kv.jsonl":      `{"prompt":"login password=unredactedpw failed","completion":"[AUTH-BRUTEFORCE]"}` + "\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if _, err := ValidateJSONLFile(p, true); err == nil {
			t.Fatalf("expected ValidateJSONLFile to reject %s", name)
		}
	}

	// Verify WriteFTaaSDataset also refuses to overwrite the curated primary queue.
	if _, err := WriteFTaaSDataset(filepath.Join(dir, DefaultFeedbackFilename), GenerateSeedDataset(1, 1), true); err == nil {
		t.Fatal("expected WriteFTaaSDataset to reject overwriting sentinel-feedback.jsonl")
	}

	// Reject arbitrary PII/email in FeedbackRecord.Label during PrepareRecord.
	if _, _, err := PrepareRecord(model.FeedbackRecord{
		Prompt:     "normal log event text",
		Completion: "[BENIGN-NOISE]",
		Label:      "alice@example.com",
	}, true); err == nil {
		t.Fatal("expected PrepareRecord to reject invalid email label")
	}

	// Reject exporting directly over the curated source queue OR another curated queue (even seed-only).
	srcPath, _ := store.PathFor(DefaultFeedbackFilename)
	if _, err := store.ExportFTaaS(DefaultFeedbackFilename, srcPath, 0, 1); err == nil {
		t.Fatal("expected ExportFTaaS to reject overwriting the curated source queue")
	}
	if _, err := store.ExportFTaaS("", srcPath, 1, 1); err == nil {
		t.Fatal("expected seed-only ExportFTaaS to reject overwriting primary curated queue")
	}
	otherQueueName, _ := NamedFilename("team-other")
	if _, err := store.Append(otherQueueName, rec); err != nil {
		t.Fatalf("Append team-other: %v", err)
	}
	otherQueuePath, _ := store.PathFor(otherQueueName)
	if _, err := store.ExportFTaaS(DefaultFeedbackFilename, otherQueuePath, 0, 1); err == nil {
		t.Fatal("expected ExportFTaaS to reject overwriting another existing curated queue")
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
	seenPrompts := make(map[string]int, len(recs))
	for _, r := range recs {
		seenPrompts[r.Prompt]++
	}
	for w := 0; w < writers; w++ {
		for i := 0; i < perWriter; i++ {
			want := fmt.Sprintf("service=api writer=%d seq=%d test log event", w, i)
			if seenPrompts[want] != 1 {
				t.Fatalf("expected prompt %q exactly once, got %d", want, seenPrompts[want])
			}
		}
	}
}

func TestAlertJournalRecordFindCapRedactionAndSafety(t *testing.T) {
	dir := t.TempDir()
	j := NewAlertJournal(dir)
	j.maxRecords = 3

	for i := 1; i <= 5; i++ {
		if err := j.Record(emit.Alert{
			AlertID:           fmt.Sprintf("  sentinel-100-%d  ", i),
			Service:           "alertsvc-owner@example.com",
			TemplateID:        "tmpl-owner@example.com",
			TraceID:           "trace-user@example.com",
			SourceService:     "svc-owner@example.com",
			Severity:          "HIGH",
			Message:           "user=alice@example.com ssn=123-45-6789 Authorization: Bearer secretToken12345",
			SanitizedSample:   "Authorization: Basic dXNlcjpwYXNz",
			TriageExplanation: "Echoed Bearer secretToken12345 in explanation",
			TriageAdapter:     "artifacts/password=adaptersecret/model",
			TopSurprisalFeatures: map[string]float64{
				"entropy":       3.2,
				"a@example.com": 1.1,
				"b@example.com": 2.2,
			},
		}); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
	// Reject alert with empty AlertID before modifying journal.
	if err := j.Record(emit.Alert{AlertID: "", Severity: "HIGH", Message: "missing id"}); err == nil {
		t.Fatal("expected AlertJournal.Record to reject empty AlertID")
	}

	if _, found, err := j.FindByID("sentinel-100-1"); err != nil || found {
		t.Fatalf("expected oldest alert sentinel-100-1 to be evicted, found=%v err=%v", found, err)
	}
	got, found, err := j.FindByID("sentinel-100-5")
	if err != nil || !found || got.AlertID != "sentinel-100-5" {
		t.Fatalf("expected newest trimmed alert sentinel-100-5, got=%+v found=%v err=%v", got, found, err)
	}
	if len(got.TopSurprisalFeatures) != 1 || got.TopSurprisalFeatures["entropy"] != 3.2 {
		t.Fatalf("expected redacted feature keys to be omitted deterministically while preserving clean keys, got %+v", got.TopSurprisalFeatures)
	}
	// Verify in-place upsert on an existing AlertID replaces the record without duplicating rows.
	updated := got
	updated.Tier = "tier0+tier2"
	updated.TriageClass = "AUTH-BRUTEFORCE"
	if err := j.Record(updated); err != nil {
		t.Fatalf("upsert Record failed: %v", err)
	}
	gotUpsert, foundUpsert, err := j.FindByID("sentinel-100-5")
	if err != nil || !foundUpsert || gotUpsert.Tier != "tier0+tier2" || gotUpsert.TriageClass != "AUTH-BRUTEFORCE" {
		t.Fatalf("expected in-place upserted alert, got=%+v found=%v err=%v", gotUpsert, foundUpsert, err)
	}
	allRecent, err := j.Recent(10)
	if err != nil || len(allRecent) != 3 {
		t.Fatalf("expected upsert to preserve 3 unique alert rows without duplication, got len=%d err=%v", len(allRecent), err)
	}
	// Verify PII/secrets (including Service, TemplateID, SourceService, TraceID, TriageAdapter, feature keys) were scrubbed before persistence in alerts.jsonl.
	rawJournal, err := os.ReadFile(j.Path())
	if err != nil {
		t.Fatalf("read alerts.jsonl: %v", err)
	}
	for _, secret := range []string{"alertsvc-owner@example.com", "tmpl-owner@example.com", "trace-user@example.com", "svc-owner@example.com", "alice@example.com", "a@example.com", "b@example.com", "adaptersecret", "123-45-6789", "secretToken12345", "dXNlcjpwYXNz"} {
		if strings.Contains(string(rawJournal), secret) {
			t.Fatalf("secret %q leaked into alerts.jsonl: %s", secret, string(rawJournal))
		}
	}

	recent, err := j.Recent(2)
	if err != nil || len(recent) != 2 || recent[0].AlertID != "sentinel-100-5" {
		t.Fatalf("unexpected Recent(2): %+v err=%v", recent, err)
	}

	// Verify malformed existing journal row fails closed rather than silently rewriting over history.
	corruptDir := t.TempDir()
	jCorrupt := NewAlertJournal(corruptDir)
	if err := os.WriteFile(jCorrupt.Path(), []byte(`{"alert_id":"ok-1"}`+"\n{not-valid-json\n"), 0600); err != nil {
		t.Fatalf("write corrupt alerts.jsonl: %v", err)
	}
	if err := jCorrupt.Record(emit.Alert{AlertID: "ok-2", Severity: "HIGH"}); err == nil {
		t.Fatal("expected Record to refuse overwriting a journal containing a malformed row")
	}

	// Verify oversized record is rejected with a clear record-size error WITHOUT modifying existing
	// journal bytes (seeded in an isolated directory strictly below the reduced cap), AND when
	// mixed with a valid sibling alert in one batch, the valid sibling is still persisted.
	isoDir := t.TempDir()
	jSmall := NewAlertJournal(isoDir)
	jSmall.maxBytes = 1024
	jSmall.maxRecordBytes = 1024
	if err := jSmall.Record(emit.Alert{AlertID: "sentinel-seed", Severity: "LOW", Message: "small seed"}); err != nil {
		t.Fatalf("seed isolated journal: %v", err)
	}
	beforeBytes, err := os.ReadFile(jSmall.Path())
	if err != nil {
		t.Fatalf("read isolated journal before: %v", err)
	}
	if err := jSmall.Record(emit.Alert{
		AlertID: "sentinel-too-big",
		Message: strings.Repeat("X", 2048),
	}); err == nil || !strings.Contains(err.Error(), "exceeds journal limit") {
		t.Fatalf("expected record-size limit error, got %v", err)
	}
	afterBytes, err := os.ReadFile(jSmall.Path())
	if err != nil || string(afterBytes) != string(beforeBytes) {
		t.Fatalf("oversized single-record rejection altered isolated journal bytes")
	}
	if err := jSmall.Record(
		emit.Alert{AlertID: "sentinel-too-big-2", Message: strings.Repeat("Y", 2048)},
		emit.Alert{AlertID: "sentinel-good-sibling", Severity: "MEDIUM", Message: "sibling fits"},
	); err == nil {
		t.Fatal("expected error for oversized record in mixed batch")
	}
	if _, found, err := jSmall.FindByID("sentinel-good-sibling"); err != nil || !found {
		t.Fatalf("expected valid sibling alert to persist despite oversized neighbor, found=%v err=%v", found, err)
	}

	// Verify enabling redaction scrubs retained unredacted rows on the next rewrite.
	reRedactDir := t.TempDir()
	jUnred := NewAlertJournalWithRedaction(reRedactDir, false)
	if err := jUnred.Record(emit.Alert{AlertID: "sentinel-old-email", Severity: "LOW", Message: "contact legacy@example.com"}); err != nil {
		t.Fatalf("seed unredacted journal: %v", err)
	}
	jRed := NewAlertJournalWithRedaction(reRedactDir, true)
	if err := jRed.Record(emit.Alert{AlertID: "sentinel-new-clean", Severity: "LOW", Message: "clean alert"}); err != nil {
		t.Fatalf("rewrite with redaction enabled: %v", err)
	}
	rawRewritten, err := os.ReadFile(jRed.Path())
	if err != nil {
		t.Fatalf("read rewritten journal: %v", err)
	}
	if strings.Contains(string(rawRewritten), "legacy@example.com") {
		t.Fatalf("retained unredacted email survived rewrite with redaction enabled: %s", string(rawRewritten))
	}
	if _, found, err := jRed.FindByID("sentinel-old-email"); err != nil || !found {
		t.Fatalf("expected AlertID sentinel-old-email to remain lookupable after redaction rewrite, found=%v err=%v", found, err)
	}

	// Verify read error does NOT overwrite/wipe the existing journal (Unix chmod semantics).
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		unreadableDir := t.TempDir()
		jErr := NewAlertJournal(unreadableDir)
		if err := jErr.Record(emit.Alert{AlertID: "sentinel-keep", Severity: "HIGH"}); err != nil {
			t.Fatalf("seed journal: %v", err)
		}
		if err := os.Chmod(jErr.Path(), 0000); err != nil {
			t.Fatalf("chmod 0000: %v", err)
		}
		defer func() { _ = os.Chmod(jErr.Path(), 0600) }()
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

	// Verify UpdateIfPresent updates existing alerts in-place AND never re-inserts/evicts
	// newer alerts when an older alert has already aged out of the bounded journal ring.
	jRing := NewAlertJournal(t.TempDir())
	jRing.maxRecords = 1
	if err := jRing.Record(emit.Alert{AlertID: "alert-A", Severity: "LOW", Tier: "tier0"}); err != nil {
		t.Fatalf("Record A: %v", err)
	}
	if err := jRing.Record(emit.Alert{AlertID: "alert-B", Severity: "HIGH", Tier: "tier0"}); err != nil {
		t.Fatalf("Record B: %v", err)
	}
	// alert-A aged out; delayed async Tier 2 update for alert-A must NOT evict alert-B!
	if err := jRing.UpdateIfPresent(emit.Alert{AlertID: "alert-A", Severity: "LOW", Tier: "tier0+tier2"}); err != nil {
		t.Fatalf("UpdateIfPresent aged-out A: %v", err)
	}
	if _, foundB, err := jRing.FindByID("alert-B"); err != nil || !foundB {
		t.Fatalf("delayed UpdateIfPresent for aged-out A evicted B: found=%v err=%v", foundB, err)
	}
	if err := jRing.UpdateIfPresent(emit.Alert{AlertID: "alert-B", Severity: "HIGH", Tier: "tier0+tier2", TriageClass: "AUTH-BRUTEFORCE"}); err != nil {
		t.Fatalf("UpdateIfPresent B: %v", err)
	}
	gotB, foundB, err := jRing.FindByID("alert-B")
	if err != nil || !foundB || gotB.Tier != "tier0+tier2" || gotB.TriageClass != "AUTH-BRUTEFORCE" {
		t.Fatalf("expected UpdateIfPresent to upgrade alert-B in-place, got=%+v found=%v err=%v", gotB, foundB, err)
	}
	_ = config.DefaultMaxTrainingFileBytes
}

func TestHelperProcessDirLock(t *testing.T) {
	dir := os.Getenv("SENTINEL_TEST_LOCK_HELPER_DIR")
	if dir == "" {
		return
	}
	unlock, err := AcquireDirLock(dir)
	if err != nil {
		t.Fatalf("helper AcquireDirLock: %v", err)
	}
	defer unlock()
	marker := filepath.Join(dir, "child-acquired.marker")
	if err := os.WriteFile(marker, []byte("ok"), 0600); err != nil {
		t.Fatalf("helper write marker: %v", err)
	}
}

func TestAcquireDirLockSerializesSeparateOSProcesses(t *testing.T) {
	dir := t.TempDir()
	unlock, err := AcquireDirLock(dir)
	if err != nil {
		t.Fatalf("parent AcquireDirLock: %v", err)
	}
	released := false
	defer func() {
		if !released {
			unlock()
		}
	}()

	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcessDirLock$")
	cmd.Env = append(os.Environ(), "SENTINEL_TEST_LOCK_HELPER_DIR="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start lock helper process: %v", err)
	}
	doneCh := make(chan error, 1)
	go func() { doneCh <- cmd.Wait() }()

	// While parent holds the OS directory lock, child process MUST wait and not acquire it.
	select {
	case err := <-doneCh:
		t.Fatalf("child OS process bypassed held directory lock (err=%v)", err)
	case <-time.After(150 * time.Millisecond):
	}
	if _, statErr := os.Stat(filepath.Join(dir, "child-acquired.marker")); !os.IsNotExist(statErr) {
		t.Fatal("child process wrote marker while parent still held OS directory lock")
	}

	unlock()
	released = true

	select {
	case err := <-doneCh:
		if err != nil {
			t.Fatalf("child lock helper failed after parent release: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child process did not acquire directory lock after parent released it")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "child-acquired.marker")); statErr != nil {
		t.Fatalf("child process did not create marker after acquiring lock: %v", statErr)
	}
}
