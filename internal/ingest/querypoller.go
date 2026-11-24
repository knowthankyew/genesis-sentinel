package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
)

const (
	// DefaultMaxQueryResponseBytes caps a single /query HTTP response body to bound memory.
	DefaultMaxQueryResponseBytes = 32 * 1024 * 1024 // 32 MiB
)

// ErrQueryResponseTooLarge is returned when Genesis /query exceeds MaxResponseBytes.
var ErrQueryResponseTooLarge = errors.New("genesis /query response exceeds max byte bound")

// QueryPollerStats tracks cursor, page-saturation, and observed eviction-gap telemetry
// for volatile /query polling.
type QueryPollerStats struct {
	LastTimestamp  int64  `json:"last_timestamp"`
	LastID         uint64 `json:"last_id"`
	Polls          uint64 `json:"polls"`
	EventsRead     uint64 `json:"events_read"`
	EvictionGaps   uint64 `json:"eviction_gaps"`
	EstimatedLost  uint64 `json:"estimated_lost"`
	SaturatedPages uint64 `json:"saturated_pages"`
}

// QueryPoller is the secondary volatile-mode fallback reader that polls Genesis
// GET /query windows over loopback HTTP, explicitly tracking ID eviction gaps
// and serializing polls so overlapping calls never duplicate events.
type QueryPoller struct {
	pollGate         chan struct{} // 1-slot semaphore for context-aware Poll serialization
	mu               sync.Mutex    // guards cursor & stats for concurrent Reset/Stats calls
	baseURL          string
	authToken        string
	client           *http.Client
	limit            int
	maxResponseBytes int64

	resetGen    uint64
	initialized bool
	lastTs      int64
	lastID      uint64

	polls          uint64
	eventsRead     uint64
	evictionGaps   uint64
	estimatedLost  uint64
	saturatedPages uint64
}

type genesisQueryResponse struct {
	Count     int              `json:"count"`
	LatencyUs int64            `json:"latency_us"`
	Logs      []model.LogEvent `json:"logs"`
}

// NewQueryPoller initializes a cursor-based poller targeting Genesis's HTTP /query API.
// Redirects to non-loopback hosts are rejected unless allowRemote is true.
func NewQueryPoller(baseURL, authToken string, limit int, allowRemote bool) *QueryPoller {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	return &QueryPoller{
		pollGate:         make(chan struct{}, 1),
		baseURL:          strings.TrimRight(baseURL, "/"),
		authToken:        authToken,
		limit:            limit,
		maxResponseBytes: DefaultMaxQueryResponseBytes,
		client:           security.NewLoopbackHTTPClient(5*time.Second, allowRemote, false),
	}
}

// SetMaxResponseBytes overrides the response byte limit (primarily for testing).
func (p *QueryPoller) SetMaxResponseBytes(n int64) {
	p.mu.Lock()
	if n > 0 {
		p.maxResponseBytes = n
	}
	p.mu.Unlock()
}

// Reset clears the in-memory query cursor and increments the reset generation so
// an in-flight Poll started before Reset cannot restore a pre-burn cursor.
func (p *QueryPoller) Reset() {
	p.mu.Lock()
	p.resetGen++
	p.initialized = false
	p.lastTs = 0
	p.lastID = 0
	p.mu.Unlock()
}

// Poll fetches unseen LogEvents from Genesis starting at the previous timestamp cursor.
// Concurrent Poll calls are serialized with context-aware waiting so canceled callers
// return immediately while active callers deliver and count each new ID once.
func (p *QueryPoller) Poll(ctx context.Context) ([]model.LogEvent, error) {
	select {
	case p.pollGate <- struct{}{}:
		defer func() { <-p.pollGate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	p.mu.Lock()
	gen := p.resetGen
	startTs := p.lastTs
	lastID := p.lastID
	initialized := p.initialized
	maxBytes := p.maxResponseBytes
	p.mu.Unlock()

	q := url.Values{}
	q.Set("order", "asc")
	q.Set("limit", strconv.Itoa(p.limit))
	if startTs > 0 {
		q.Set("start", strconv.FormatInt(startTs, 10))
	}

	reqURL := p.baseURL + "/query?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	if p.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+p.authToken)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("genesis /query returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	// Enforce response byte ceiling before JSON decoding so an oversized payload cannot OOM the poller.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read genesis /query response: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("%w (%d bytes limit)", ErrQueryResponseTooLarge, maxBytes)
	}

	var parsed *genesisQueryResponse
	if err := json.Unmarshal(body, &parsed); err != nil || parsed == nil {
		if err == nil {
			err = fmt.Errorf("unexpected null JSON payload")
		}
		return nil, fmt.Errorf("decode genesis /query response: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// If Reset() occurred while HTTP request was in flight, discard pre-burn results cleanly.
	if p.resetGen != gen {
		return nil, nil
	}

	p.polls++

	if len(parsed.Logs) == 0 {
		return nil, nil
	}

	// Detect observed eviction or drop gaps strictly across rows newer than lastID.
	if initialized && lastID > 0 {
		var minNewID uint64
		foundNew := false
		for _, ev := range parsed.Logs {
			if ev.ID <= lastID {
				continue
			}
			if !foundNew || ev.ID < minNewID {
				minNewID = ev.ID
				foundNew = true
			}
		}
		if foundNew && minNewID > lastID+1 {
			p.evictionGaps++
			p.estimatedLost += minNewID - lastID - 1
		}
	}

	var unseen []model.LogEvent
	maxTs := p.lastTs
	maxID := p.lastID
	for _, ev := range parsed.Logs {
		if initialized && ev.ID <= lastID {
			continue
		}
		unseen = append(unseen, ev)
		if ev.Timestamp > maxTs {
			maxTs = ev.Timestamp
		}
		if ev.ID > maxID {
			maxID = ev.ID
		}
	}

	if len(parsed.Logs) >= p.limit {
		// Track full query-page saturation separately from observed ID loss.
		p.saturatedPages++
	}

	p.initialized = true
	p.lastTs = maxTs
	p.lastID = maxID
	p.eventsRead += uint64(len(unseen))
	return unseen, nil
}

// Stats returns a snapshot of QueryPoller telemetry.
func (p *QueryPoller) Stats() QueryPollerStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return QueryPollerStats{
		LastTimestamp:  p.lastTs,
		LastID:         p.lastID,
		Polls:          p.polls,
		EventsRead:     p.eventsRead,
		EvictionGaps:   p.evictionGaps,
		EstimatedLost:  p.estimatedLost,
		SaturatedPages: p.saturatedPages,
	}
}
