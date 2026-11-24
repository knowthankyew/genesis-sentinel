package cli

import (
	"bytes"
	"encoding/json"
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
