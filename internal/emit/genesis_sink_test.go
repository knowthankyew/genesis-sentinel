package emit

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

func TestShouldIgnoreEventLoopPrevention(t *testing.T) {
	if !ShouldIgnoreEvent(model.LogEvent{Service: "sentinel"}, "sentinel") {
		t.Fatal("expected exact sentinel service match to be ignored")
	}
	if !ShouldIgnoreEvent(model.LogEvent{Service: "SENTINEL"}, "sentinel") {
		t.Fatal("expected case-insensitive sentinel service match to be ignored")
	}
	if !ShouldIgnoreEvent(model.LogEvent{Service: "sentinel"}, "custom-alerts") {
		t.Fatal("expected reserved sentinel service to always be ignored even with custom alertService")
	}
	if !ShouldIgnoreEvent(model.LogEvent{Service: "custom-alerts"}, "custom-alerts") {
		t.Fatal("expected custom alertService to be ignored")
	}
	if ShouldIgnoreEvent(model.LogEvent{Service: "sshd"}, "sentinel") {
		t.Fatal("did not expect sshd to be ignored")
	}
}

func TestGenesisTCPSinkEmitsValidGenesisJSONLine(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type readResult struct {
		line string
		err  error
	}
	received := make(chan readResult, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			received <- readResult{err: acceptErr}
			return
		}
		defer func() { _ = conn.Close() }()
		line, readErr := bufio.NewReader(conn).ReadString('\n')
		received <- readResult{line: line, err: readErr}
	}()

	sink := NewGenesisTCPSink(ln.Addr().String(), 2*time.Second)
	defer func() { _ = sink.Close() }()

	alert := Alert{
		Timestamp:     1763996400,
		Service:       "sentinel",
		Level:         MapSeverityToGenesisLevel("HIGH"),
		TraceID:       "alert-1",
		Message:       "[SENT-001] auth_bruteforce on sshd (count=12)",
		AlertID:       "alert-1",
		Tier:          "tier0",
		SourceService: "sshd",
		Severity:      "HIGH",
		Count:         12,
		RuleIDs:       []string{"SENT-001"},
	}

	if err := sink.Emit(alert); err != nil {
		t.Fatalf("Emit failed: %v", err)
	}

	select {
	case res := <-received:
		if res.err != nil {
			t.Fatalf("expected newline-terminated JSON line with nil read error, got err=%v line=%q", res.err, res.line)
		}
		var decoded Alert
		if err := json.Unmarshal([]byte(res.line), &decoded); err != nil {
			t.Fatalf("received line not valid JSON: %v (raw=%q)", err, res.line)
		}
		if decoded.Service != "sentinel" || decoded.Level != "ERROR" || decoded.AlertID != "alert-1" {
			t.Fatalf("unexpected decoded alert: %+v", decoded)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for TCP alert")
	}
}

func TestGenesisTCPSinkLoopbackPolicyRejectsRemoteAndDialsLocalhost(t *testing.T) {
	alert := Alert{
		Timestamp:     1763996400,
		Service:       "sentinel",
		Level:         "ERROR",
		TraceID:       "alert-loopback-check",
		Message:       "test alert",
		AlertID:       "alert-loopback-check",
		Tier:          "tier0",
		SourceService: "sshd",
		Severity:      "HIGH",
		Count:         1,
	}

	// 1. Default loopback policy must fail closed at dial time on non-loopback targets without opening external sockets.
	remoteSink := NewGenesisTCPSink("203.0.113.10:9000", 150*time.Millisecond)
	defer func() { _ = remoteSink.Close() }()
	err := remoteSink.Emit(alert)
	if err == nil || !strings.Contains(err.Error(), "refusing non-loopback dial target") {
		t.Fatalf("expected dial-time loopback policy rejection for 203.0.113.10:9000, got err=%v", err)
	}

	// 2. Hostname "localhost:<port>" must dial loopback IP literals directly via DialLoopbackContext.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp4: %v", err)
	}
	defer func() { _ = ln.Close() }()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}

	done := make(chan string, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			done <- ""
			return
		}
		defer func() { _ = conn.Close() }()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		done <- line
	}()

	localhostSink := NewGenesisTCPSink(net.JoinHostPort("localhost", port), 2*time.Second)
	defer func() { _ = localhostSink.Close() }()
	if err := localhostSink.Emit(alert); err != nil {
		t.Fatalf("expected localhost dial via DialLoopbackContext to succeed, got: %v", err)
	}
	select {
	case line := <-done:
		if !strings.Contains(line, `"alert-loopback-check"`) {
			t.Fatalf("unexpected TCP payload: %q", line)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for localhost TCP alert")
	}
}
