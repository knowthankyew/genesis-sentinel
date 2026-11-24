package emit

import (
	"bufio"
	"encoding/json"
	"net"
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

	received := make(chan string, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		received <- line
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
	case line := <-received:
		var decoded Alert
		if err := json.Unmarshal([]byte(line), &decoded); err != nil {
			t.Fatalf("received line not valid JSON: %v (raw=%q)", err, line)
		}
		if decoded.Service != "sentinel" || decoded.Level != "ERROR" || decoded.AlertID != "alert-1" {
			t.Fatalf("unexpected decoded alert: %+v", decoded)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for TCP alert")
	}
}
