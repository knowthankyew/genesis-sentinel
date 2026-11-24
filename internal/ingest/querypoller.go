package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

// QueryPollerStats tracks cursor and eviction-gap telemetry for volatile /query polling.
type QueryPollerStats struct {
	LastTimestamp int64  `json:"last_timestamp"`
	LastID        uint64 `json:"last_id"`
	Polls         uint64 `json:"polls"`
	EventsRead    uint64 `json:"events_read"`
	EvictionGaps  uint64 `json:"eviction_gaps"`
	EstimatedLost uint64 `json:"estimated_lost"`
}

// QueryPoller is the secondary volatile-mode fallback reader that polls Genesis
// GET /query windows over loopback HTTP, explicitly tracking ID eviction gaps.
type QueryPoller struct {
	mu          sync.Mutex
	baseURL     string
	authToken   string
	client      *http.Client
	limit       int
	initialized bool
	lastTs      int64
	lastID      uint64

	polls         uint64
	eventsRead    uint64
	evictionGaps  uint64
	estimatedLost uint64
}

type genesisQueryResponse struct {
	Count     int              `json:"count"`
	LatencyUs int64            `json:"latency_us"`
	Logs      []model.LogEvent `json:"logs"`
}

// NewQueryPoller initializes a cursor-based poller targeting Genesis's HTTP /query API.
func NewQueryPoller(baseURL, authToken string, limit int) *QueryPoller {
	if limit <= 0 || limit > 10000 {
		limit = 10000
	}
	return &QueryPoller{
		baseURL:   strings.TrimRight(baseURL, "/"),
		authToken: authToken,
		limit:     limit,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

// Poll fetches unseen LogEvents from Genesis starting at the previous timestamp cursor.
func (p *QueryPoller) Poll(ctx context.Context) ([]model.LogEvent, error) {
	p.mu.Lock()
	startTs := p.lastTs
	lastID := p.lastID
	initialized := p.initialized
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

	var parsed genesisQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("decode genesis /query response: %w", err)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.polls++

	if len(parsed.Logs) == 0 {
		return nil, nil
	}

	// Detect eviction or drop gaps using Genesis's monotonic LogEntry.ID counter.
	if initialized && lastID > 0 {
		minReturnedID := parsed.Logs[0].ID
		for _, ev := range parsed.Logs[1:] {
			if ev.ID < minReturnedID {
				minReturnedID = ev.ID
			}
		}
		if minReturnedID > lastID+1 {
			p.evictionGaps++
			p.estimatedLost += minReturnedID - lastID - 1
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
		// Saturated the 10,000-row query ceiling; record a potential gap warning.
		p.evictionGaps++
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
		LastTimestamp: p.lastTs,
		LastID:        p.lastID,
		Polls:         p.polls,
		EventsRead:    p.eventsRead,
		EvictionGaps:  p.evictionGaps,
		EstimatedLost: p.estimatedLost,
	}
}
