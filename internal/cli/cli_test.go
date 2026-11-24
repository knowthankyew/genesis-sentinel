package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExecuteVersionAndHelp(t *testing.T) {
	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"version"}, &out, &errBuf); err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	if !strings.Contains(out.String(), Version) {
		t.Fatalf("expected version %q in output, got %q", Version, out.String())
	}

	out.Reset()
	if err := ExecuteWithOutput([]string{"help"}, &out, &errBuf); err != nil {
		t.Fatalf("help command failed: %v", err)
	}
	if !strings.Contains(out.String(), "Genesis Sentinel") {
		t.Fatalf("unexpected help output: %q", out.String())
	}
}

func TestExecuteConfigRedactsTokens(t *testing.T) {
	t.Setenv("SENTINEL_AUTH_TOKEN", "super-secret-sentinel-token")
	t.Setenv("SENTINEL_GENESIS_AUTH_TOKEN", "super-secret-genesis-token")

	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"config"}, &out, &errBuf); err != nil {
		t.Fatalf("config command failed: %v", err)
	}

	if strings.Contains(out.String(), "super-secret") {
		t.Fatal("config output leaked raw auth token")
	}

	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("config output is not valid JSON: %v", err)
	}
	if decoded["auth_token"] != "[REDACTED]" || decoded["genesis_auth_token"] != "[REDACTED]" {
		t.Fatalf("expected tokens to be redacted, got auth_token=%v genesis_auth_token=%v",
			decoded["auth_token"], decoded["genesis_auth_token"])
	}
}

func TestExecuteUnknownCommandAndPhase3Stubs(t *testing.T) {
	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"bogus"}, &out, &errBuf); err == nil {
		t.Fatal("expected error for unknown command")
	}
	if err := ExecuteWithOutput([]string{"train"}, &out, &errBuf); err == nil {
		t.Fatal("expected Phase 3 roadmap stub error for train")
	}
	if err := ExecuteWithOutput([]string{"feedback"}, &out, &errBuf); err == nil {
		t.Fatal("expected Phase 3 roadmap stub error for feedback")
	}
}

func TestExecuteScanSyntheticJSON(t *testing.T) {
	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"scan", "--synthetic", "5000", "--json"}, &out, &errBuf); err != nil {
		t.Fatalf("scan --synthetic failed: %v (stderr=%s)", err, errBuf.String())
	}

	var rep ScanReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode scan JSON: %v", err)
	}
	if rep.LinesRead != 5000 {
		t.Fatalf("LinesRead = %d, want 5000", rep.LinesRead)
	}
	if rep.AlertsEmitted < 6 {
		t.Fatalf("expected >= 6 alerts covering all starter classes, got %d", rep.AlertsEmitted)
	}
	if rep.CollapseRatio < 100 {
		t.Fatalf("expected strong collapse ratio (>100x), got %.2f", rep.CollapseRatio)
	}
}

func TestExecuteScanFileContinuesPastOversizedLine(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "mixed.log")
	oversized := strings.Repeat("X", 1024*1024+128) + "\n"
	content := `{"timestamp":1763996400,"service":"api","level":"INFO","message":"before oversized"}` + "\n" +
		oversized +
		`{"timestamp":1763996401,"service":"nginx","level":"WARN","message":"GET /../../etc/passwd HTTP/1.1 403"}` + "\n"
	if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
		t.Fatalf("write mixed.log: %v", err)
	}

	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"scan", "--file", tmpFile, "--json"}, &out, &errBuf); err != nil {
		t.Fatalf("scan --file failed: %v", err)
	}
	var rep ScanReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode scan JSON: %v", err)
	}
	if rep.OversizedLines != 1 || rep.LinesRead != 2 || rep.AlertsEmitted != 1 {
		t.Fatalf("expected OversizedLines=1 LinesRead=2 AlertsEmitted=1, got %+v", rep)
	}
}

func TestExecuteScanFileExactMaxFramePayloadBoundaries(t *testing.T) {
	// Verify exact 1 MiB payload passes with LF, CRLF, and EOF, while 1 MiB + 1 byte is skipped.
	prefix := `{"timestamp":1763996400,"service":"api","level":"INFO","message":"`
	suffix := `"}`
	padLen := 1024*1024 - len(prefix) - len(suffix)
	exactPayload := prefix + strings.Repeat("a", padLen) + suffix
	overPayload := prefix + strings.Repeat("b", padLen+1) + suffix

	tmpFile := filepath.Join(t.TempDir(), "bounds.log")
	content := exactPayload + "\n" + exactPayload + "\r\n" + overPayload + "\n" + exactPayload
	if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
		t.Fatalf("write bounds.log: %v", err)
	}

	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"scan", "--file", tmpFile, "--json"}, &out, &errBuf); err != nil {
		t.Fatalf("scan bounds.log failed: %v", err)
	}
	var rep ScanReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode scan JSON: %v", err)
	}
	if rep.LinesRead != 3 || rep.OversizedLines != 1 {
		t.Fatalf("expected 3 exact-limit payloads read (LF, CRLF, EOF) and 1 oversized skipped, got %+v", rep)
	}
}

func TestExecuteStatsEscapesControlBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("raw \x1b[31mred\x1b[0m text"))
	}))
	defer srv.Close()

	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"stats", "--http", srv.URL}, &out, &errBuf); err != nil {
		t.Fatalf("stats non-JSON failed: %v", err)
	}
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Fatalf("stats output leaked raw terminal ESC byte: %q", out.String())
	}
}

func TestExecuteWatchRejectsNonPositivePollInterval(t *testing.T) {
	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"watch", "--poll-interval", "0s"}, &out, &errBuf); err == nil {
		t.Fatal("expected watch --poll-interval=0s to return error")
	}
}

func TestExecuteStatsAndBurn(t *testing.T) {
	// Test `sentinel stats` against loopback httptest server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stats" && r.Header.Get("Authorization") == "Bearer tok-stat" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"lines_read":1234,"alerts_emitted":2}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"stats", "--http", srv.URL, "--auth-token", "tok-stat"}, &out, &errBuf); err != nil {
		t.Fatalf("stats command failed: %v", err)
	}
	if !strings.Contains(out.String(), `"lines_read": 1234`) {
		t.Fatalf("unexpected stats output: %s", out.String())
	}

	// Test `sentinel burn` requires -y, then purges local state cleanly
	tmp := filepath.Join(t.TempDir(), ".genesis-sentinel")
	t.Setenv("SENTINEL_DATA_DIR", tmp)
	if err := os.MkdirAll(tmp, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "cursor.json"), []byte(`{"segment_id":2}`), 0600); err != nil {
		t.Fatalf("write cursor: %v", err)
	}

	out.Reset()
	if err := ExecuteWithOutput([]string{"burn"}, &out, &errBuf); err == nil {
		t.Fatal("expected burn without -y to fail")
	}

	out.Reset()
	if err := ExecuteWithOutput([]string{"burn", "-y"}, &out, &errBuf); err != nil {
		t.Fatalf("burn -y failed: %v", err)
	}
	if !strings.Contains(out.String(), `"status": "burned"`) {
		t.Fatalf("unexpected burn output: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(tmp, "cursor.json")); !os.IsNotExist(err) {
		t.Fatal("cursor.json survived burn -y")
	}

	// Plain-text HTTP 200 response from --http burn endpoint must return an error, not false success.
	badBurnSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK plain text not a burn report"))
	}))
	defer badBurnSrv.Close()

	out.Reset()
	if err := ExecuteWithOutput([]string{"burn", "-y", "--http", badBurnSrv.URL}, &out, &errBuf); err == nil {
		t.Fatal("expected burn --http to fail on non-JSON BurnReport response")
	}
}

func TestExecuteDataSubcommands(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), ".genesis-sentinel")
	t.Setenv("SENTINEL_DATA_DIR", tmp)

	// 1. `sentinel data path`
	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"data", "path"}, &out, &errBuf); err != nil {
		t.Fatalf("data path failed: %v", err)
	}
	if strings.TrimSpace(out.String()) != tmp {
		t.Fatalf("data path = %q, want %q", strings.TrimSpace(out.String()), tmp)
	}

	// 2. `sentinel data status` before creation
	out.Reset()
	if err := ExecuteWithOutput([]string{"data", "status"}, &out, &errBuf); err != nil {
		t.Fatalf("data status failed: %v", err)
	}
	var st dataDirStatus
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
		t.Fatalf("invalid status JSON: %v", err)
	}
	if st.Exists || st.FileCount != 0 {
		t.Fatalf("expected non-existent empty dir, got %+v", st)
	}

	// 3. `sentinel data open` uses injectable opener and creates dir cleanly
	var opened string
	origOpen := openDirFn
	openDirFn = func(dir string) error {
		opened = dir
		return nil
	}
	defer func() { openDirFn = origOpen }()

	out.Reset()
	if err := ExecuteWithOutput([]string{"data", "open"}, &out, &errBuf); err != nil {
		t.Fatalf("data open failed: %v", err)
	}
	if opened != tmp {
		t.Fatalf("openDirFn called with %q, want %q", opened, tmp)
	}

	// 4. Write a sample file and verify `sentinel data status` counts bytes accurately
	if err := os.WriteFile(filepath.Join(tmp, "cursor.json"), []byte(`{"seg":1}`), 0600); err != nil {
		t.Fatalf("failed writing sample file: %v", err)
	}
	out.Reset()
	if err := ExecuteWithOutput([]string{"data", "status"}, &out, &errBuf); err != nil {
		t.Fatalf("data status failed: %v", err)
	}
	st = dataDirStatus{}
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
		t.Fatalf("invalid status JSON: %v", err)
	}
	if !st.Exists || st.FileCount != 1 || st.TotalBytes != 9 {
		t.Fatalf("unexpected data status after write: %+v", st)
	}
}
