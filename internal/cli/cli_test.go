package cli

import (
	"bytes"
	"encoding/json"
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

func TestExecuteUnknownCommandAndStubs(t *testing.T) {
	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"bogus"}, &out, &errBuf); err == nil {
		t.Fatal("expected error for unknown command")
	}
	if err := ExecuteWithOutput([]string{"watch"}, &out, &errBuf); err == nil {
		t.Fatal("expected roadmap phase stub error for watch in Phase 0")
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
