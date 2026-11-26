package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/emit"
	"github.com/knowthankyew/genesis-sentinel/internal/feedback"
	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
	"github.com/knowthankyew/genesis-sentinel/internal/train"
	"github.com/knowthankyew/genesis-sentinel/internal/triage"
)

const (
	maxAdapterSwapHistory    = 16
	correlationWindowTTLSec  = 600
	maxCorrelationServices   = 64
	maxCorrelationPerService = 4
)

type correlationEntry struct {
	timestamp     int64
	templateID    string
	severity      string
	category      string
	count         uint64
	surprisalNats float64
	triageClass   string
}

type slotRuntimeMeta struct {
	jobID       string
	datasetHash string
	swappedAt   time.Time
	previous    *train.AdapterSlot
}

func buildSlotClient(
	baseURL, baseModel, adapterPath, apiKey string,
	timeoutSec, maxTokens int,
	temp float64,
	maxPromptBytes int,
	allowRemote bool,
) (*triage.Client, time.Duration, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, 0, fmt.Errorf("inference URL is empty")
	}
	flushBudget := time.Duration(timeoutSec) * time.Second
	if flushBudget <= 0 {
		flushBudget = config.DefaultTriageTimeoutSec * time.Second
	}
	reqTimeout := 10 * time.Second
	if flushBudget <= 15*time.Second {
		reqTimeout = 5 * time.Second
	}
	if flushBudget > 25*time.Second {
		// Allow larger escalation models (e.g. Gemma 2 2B IT) bounded headroom while still
		// failing promptly if the local inference service hangs.
		if timeoutSec >= 60 {
			reqTimeout = 30 * time.Second
		}
	}
	if flushBudget < reqTimeout {
		reqTimeout = flushBudget
	}
	tc, err := triage.NewClient(triage.ClientOptions{
		BaseURL:        baseURL,
		BaseModel:      baseModel,
		AdapterPath:    adapterPath,
		APIKey:         apiKey,
		Timeout:        reqTimeout,
		MaxTokens:      maxTokens,
		Temperature:    temp,
		MaxPromptBytes: maxPromptBytes,
		AllowRemote:    allowRemote,
	})
	if err != nil {
		return nil, 0, err
	}
	return tc, reqTimeout, nil
}

func (p *Pipeline) initAdapterTracking() {
	if p.cfg.DataDir == "" {
		return
	}
	hash, ok, err := readManifestSHA256(p.cfg.DataDir)
	if err == nil && ok {
		p.adapterMu.Lock()
		p.lastSyncedManifest = hash
		p.hasSyncedManifest = true
		p.adapterMu.Unlock()
	}
	manifest, exists, loadErr := train.LoadActiveAdapter(p.cfg.DataDir)
	if loadErr != nil || !exists {
		return
	}
	p.adapterMu.Lock()
	if ps, ok := manifest.PrimarySlot(); ok && ps.AdapterPath == p.cfg.AdapterPath {
		p.primaryMeta.jobID = ps.JobID
		p.primaryMeta.datasetHash = ps.DatasetHash
		p.primaryMeta.swappedAt = ps.ActivatedAt
	}
	if manifest.Previous != nil {
		cp := *manifest.Previous
		p.primaryMeta.previous = &cp
	}
	if manifest.Escalation != nil && manifest.Escalation.AdapterPath == p.cfg.EscalationAdapterPath {
		p.escalationMeta.jobID = manifest.Escalation.JobID
		p.escalationMeta.datasetHash = manifest.Escalation.DatasetHash
		p.escalationMeta.swappedAt = manifest.Escalation.ActivatedAt
	}
	if manifest.PreviousEscalation != nil {
		cp := *manifest.PreviousEscalation
		p.escalationMeta.previous = &cp
	}
	p.adapterMu.Unlock()
}

func readManifestSHA256(dataDir string) ([sha256.Size]byte, bool, error) {
	var zero [sha256.Size]byte
	if strings.TrimSpace(dataDir) == "" {
		return zero, false, nil
	}
	path := filepath.Join(dataDir, train.ActiveAdapterFilename)
	f, fi, err := feedback.OpenRegularFileNonBlocking(path)
	if err != nil {
		if os.IsNotExist(err) {
			return zero, false, nil
		}
		return zero, false, err
	}
	defer func() { _ = f.Close() }()
	if fi.Size() > 64*1024 {
		return zero, true, fmt.Errorf("active adapter manifest exceeds 64 KiB")
	}
	data, err := io.ReadAll(io.LimitReader(f, 64*1024+1))
	if err != nil {
		return zero, true, err
	}
	if len(data) > 64*1024 {
		return zero, true, fmt.Errorf("active adapter manifest exceeds 64 KiB")
	}
	return sha256.Sum256(data), true, nil
}

func (p *Pipeline) refreshSyncedManifestHashLocked() {
	hash, ok, err := readManifestSHA256(p.cfg.DataDir)
	p.adapterMu.Lock()
	p.lastSyncedManifest = hash
	p.hasSyncedManifest = err == nil && ok
	p.adapterMu.Unlock()
}

// collectCorrelatedContext returns formatted compact summaries of distinct recent prior windows
// observed on the same SourceService within correlationWindowTTLSec.
func (p *Pipeline) collectCorrelatedContext(service, excludeTemplateID string, nowUnix int64) []string {
	svc := strings.TrimSpace(service)
	if svc == "" || strings.EqualFold(svc, emit.ReservedAlertService) {
		return nil
	}
	p.corrMu.Lock()
	defer p.corrMu.Unlock()

	if len(p.serviceCorrelator) == 0 {
		return nil
	}
	entries := p.serviceCorrelator[svc]
	if len(entries) == 0 {
		return nil
	}

	out := make([]string, 0, maxCorrelationPerService)
	kept := entries[:0]
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		age := nowUnix - e.timestamp
		if age > correlationWindowTTLSec || age < -correlationWindowTTLSec {
			continue
		}
		kept = append(kept, e)
	}
	// Restore oldest->newest order in kept slice while collecting newest->oldest summary tokens.
	for i, j := 0, len(kept)-1; i < j; i, j = i+1, j-1 {
		kept[i], kept[j] = kept[j], kept[i]
	}
	if len(kept) == 0 {
		delete(p.serviceCorrelator, svc)
		return nil
	}
	p.serviceCorrelator[svc] = kept

	for i := len(kept) - 1; i >= 0 && len(out) < maxCorrelationPerService; i-- {
		e := kept[i]
		if e.templateID == excludeTemplateID {
			continue
		}
		tidShort := e.templateID
		if len(tidShort) > 8 {
			tidShort = tidShort[:8]
		}
		tag := e.category
		if e.triageClass != "" {
			tag = e.triageClass
		}
		if tag == "" {
			tag = "anomaly"
		}
		summary := fmt.Sprintf("%s(%s,%s,cnt=%d)", tidShort, tag, e.severity, e.count)
		out = append(out, summary)
	}
	return out
}

func (p *Pipeline) recordCorrelationWindow(a emit.Alert) {
	svc := strings.TrimSpace(a.SourceService)
	if svc == "" || strings.EqualFold(svc, emit.ReservedAlertService) || strings.TrimSpace(a.TemplateID) == "" {
		return
	}
	cat := "surprisal"
	if len(a.Categories) > 0 && strings.TrimSpace(a.Categories[0]) != "" {
		cat = strings.TrimSpace(a.Categories[0])
	}
	entry := correlationEntry{
		timestamp:     a.Timestamp,
		templateID:    a.TemplateID,
		severity:      a.Severity,
		category:      cat,
		count:         a.Count,
		surprisalNats: a.SurprisalNats,
		triageClass:   a.TriageClass,
	}

	p.corrMu.Lock()
	defer p.corrMu.Unlock()
	if p.serviceCorrelator == nil {
		p.serviceCorrelator = make(map[string][]correlationEntry, 8)
	}
	if _, exists := p.serviceCorrelator[svc]; !exists && len(p.serviceCorrelator) >= maxCorrelationServices {
		// Evict oldest service bucket to bound correlation state strictly.
		var oldestKey string
		var oldestTS int64 = math.MaxInt64
		for k, list := range p.serviceCorrelator {
			if len(list) == 0 {
				oldestKey = k
				break
			}
			ts := list[len(list)-1].timestamp
			if ts < oldestTS {
				oldestTS = ts
				oldestKey = k
			}
		}
		if oldestKey != "" {
			delete(p.serviceCorrelator, oldestKey)
		}
	}

	list := p.serviceCorrelator[svc]
	for i := range list {
		if list[i].templateID == entry.templateID {
			list[i] = entry
			p.serviceCorrelator[svc] = list
			return
		}
	}
	list = append(list, entry)
	if len(list) > maxCorrelationPerService {
		list = append([]correlationEntry(nil), list[len(list)-maxCorrelationPerService:]...)
	}
	p.serviceCorrelator[svc] = list
}

func severityRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func (p *Pipeline) escalationReason(alert emit.Alert, primaryVerdict model.TriageVerdict, primaryOverridden, hasPrimary, primaryFailed bool) string {
	switch p.cfg.EscalationPolicy {
	case config.EscalationPolicyAlways:
		return "policy=always"
	}

	if primaryFailed {
		return "primary_fallback"
	}
	if severityRank(alert.Severity) >= 3 || (hasPrimary && severityRank(primaryVerdict.Severity) >= 3) {
		return "severity_high_critical"
	}
	if alert.InjectionSuspected || primaryOverridden {
		return "injection_suspected"
	}
	if len(alert.CorrelatedWindows) > 0 {
		return "multi_window_correlation"
	}
	if hasPrimary && primaryVerdict.Label == triage.ClassNeedsReview {
		return "needs_review"
	}

	if p.cfg.EscalationPolicy == config.EscalationPolicyStrict {
		if hasPrimary && primaryVerdict.Confidence < p.cfg.EscalationConfidenceFloor {
			return "low_confidence"
		}
		if alert.SurprisalThreshold > 0 && alert.SurprisalNats >= alert.SurprisalThreshold*1.5 {
			return "elevated_surprisal"
		}
		for _, cat := range alert.Categories {
			switch strings.ToLower(strings.TrimSpace(cat)) {
			case "credential_access", "privilege_escalation", "exfiltration", "command_and_control", "prompt_injection":
				return "sensitive_category"
			}
		}
	}
	return ""
}

func buildPromptInputFromAlert(alert *emit.Alert) triage.PromptInput {
	return triage.PromptInput{
		Service:              alert.SourceService,
		Level:                alert.SourceLevel,
		TemplateID:           alert.TemplateID,
		Template:             alert.Template,
		SampleLine:           alert.SanitizedSample,
		Count:                alert.Count,
		SampleEntropy:        alert.SampleEntropy,
		RuleIDs:              alert.RuleIDs,
		Categories:           alert.Categories,
		SurprisalNats:        alert.SurprisalNats,
		SurprisalThreshold:   alert.SurprisalThreshold,
		TopSurprisalFeatures: alert.TopSurprisalFeatures,
		CorrelatedWindows:    alert.CorrelatedWindows,
		InjectionSuspected:   alert.InjectionSuspected,
		InjectionSignals:     alert.InjectionSignals,
	}
}

func (p *Pipeline) invokeSlotTriage(ctx context.Context, client *triage.Client, timeout time.Duration, in triage.PromptInput) (model.TriageVerdict, bool, error) {
	reqCtx := ctx
	var cancelReq context.CancelFunc
	if timeout > 0 {
		reqCtx, cancelReq = context.WithTimeout(ctx, timeout)
		defer cancelReq()
	}
	return client.TriageWindow(reqCtx, in)
}

func (p *Pipeline) enrichWithTier2(ctx context.Context, client *triage.Client, alert *emit.Alert) bool {
	return p.enrichWithTier2Dual(ctx, client, nil, alert)
}

func (p *Pipeline) enrichWithTier2Dual(ctx context.Context, primaryClient, escalationClient *triage.Client, alert *emit.Alert) bool {
	if (primaryClient == nil && escalationClient == nil) || alert == nil {
		return false
	}

	baseSeverity := alert.Severity
	baseTier := alert.Tier
	in := buildPromptInputFromAlert(alert)

	var (
		primaryVerdict    model.TriageVerdict
		primaryOverridden bool
		primaryErr        error
		hasPrimary        bool
	)
	if primaryClient != nil {
		primaryVerdict, primaryOverridden, primaryErr = p.invokeSlotTriage(ctx, primaryClient, p.triageReqTimeout, in)
		if errors.Is(primaryErr, triage.ErrStaleRuntime) {
			return false
		}
		if primaryErr == nil {
			hasPrimary = true
			alert.TriagePrimaryClass = primaryVerdict.Label
			alert.TriagePrimaryModel = primaryVerdict.ModelID
			alert.TriagePrimaryAdapter = primaryVerdict.AdapterID
		} else if ctx.Err() != nil {
			return false
		}
	}

	if escalationClient != nil {
		reason := p.escalationReason(*alert, primaryVerdict, primaryOverridden, hasPrimary, primaryClient != nil && primaryErr != nil)
		if reason != "" {
			p.escalationsTriggered.Add(1)
			escVerdict, escOverridden, escErr := p.invokeSlotTriage(ctx, escalationClient, p.escalationTimeout, in)
			if errors.Is(escErr, triage.ErrStaleRuntime) {
				return false
			}
			if escErr == nil {
				alert.TriageEscalated = true
				alert.TriageEscalationReason = reason
				alert.TriageOverridden = primaryOverridden || escOverridden
				tierSuffix := "+escalated"
				if hasPrimary {
					tierSuffix = "+tier2+escalated"
				}
				p.applyVerdictToAlert(alert, baseTier+tierSuffix, baseSeverity, escVerdict)
				return true
			}
		}
	}

	if hasPrimary {
		alert.TriageOverridden = primaryOverridden
		p.applyVerdictToAlert(alert, baseTier+"+tier2", baseSeverity, primaryVerdict)
		return true
	}
	return false
}

func (p *Pipeline) applyVerdictToAlert(alert *emit.Alert, nextTier, baseSeverity string, verdict model.TriageVerdict) {
	explanation, _ := security.SanitizeUntrustedLogText(verdict.Explanation, triage.MaxExplanationBytes*3+64)
	if p.cfg.RequireRedaction {
		explanation, _ = feedback.RedactText(explanation)
	}
	alert.Tier = nextTier
	alert.TriageClass = verdict.Label
	alert.TriageConfidence = math.Round(verdict.Confidence*1000) / 1000
	alert.TriageMitreTactic = verdict.MitreTactic
	alert.TriageExplanation = explanation
	alert.TriageModel = verdict.ModelID
	alert.TriageAdapter = verdict.AdapterID

	// Fail closed against deterministic Tier 0/1 severity (cannot downgrade rule/surprisal severity),
	// while permitting escalation tier to refine or reduce false positives above Tier 0/1 baselines.
	alert.Severity = emit.HigherSeverity(baseSeverity, verdict.Severity)
	alert.Level = emit.MapSeverityToGenesisLevel(alert.Severity)
	alert.Message = fmt.Sprintf("%s triage=[%s] %s", alert.Message, verdict.Label, truncateSummary(explanation, 160))
}

// SyncActiveAdapterFromDisk reloads active-adapter.json live when edited outside /adapter
// (e.g. direct `sentinel adapter swap` without --sentinel-http), without restarting `watch`.
func (p *Pipeline) SyncActiveAdapterFromDisk() (bool, error) {
	if !p.cfg.AutoReloadAdapter || strings.TrimSpace(p.cfg.DataDir) == "" {
		return false, nil
	}
	hash, exists, err := readManifestSHA256(p.cfg.DataDir)
	if err != nil {
		return false, err
	}
	if !exists {
		p.adapterMu.Lock()
		p.hasSyncedManifest = false
		p.lastSyncedManifest = [sha256.Size]byte{}
		p.adapterMu.Unlock()
		return false, nil
	}

	p.adapterMu.Lock()
	unchanged := p.hasSyncedManifest && p.lastSyncedManifest == hash
	p.adapterMu.Unlock()
	if unchanged {
		return false, nil
	}

	manifest, ok, err := train.LoadActiveAdapter(p.cfg.DataDir)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	p.burnMu.Lock()
	defer p.burnMu.Unlock()

	curHash, curExists, err := readManifestSHA256(p.cfg.DataDir)
	if err != nil || !curExists {
		return false, err
	}
	p.adapterMu.Lock()
	if p.hasSyncedManifest && p.lastSyncedManifest == curHash {
		p.adapterMu.Unlock()
		return false, nil
	}
	p.adapterMu.Unlock()

	swappedAny := false
	cancelAsync := false

	if ps, hasPrimary := manifest.PrimarySlot(); hasPrimary && p.triageClient != nil {
		curModel := p.triageClient.BaseModel()
		curAdapter := p.triageClient.AdapterPath()
		if curModel != ps.BaseModel || curAdapter != ps.AdapterPath {
			if err := p.triageClient.SetModelAndAdapter(ps.BaseModel, ps.AdapterPath); err != nil {
				return false, err
			}
			p.adapterEpoch.Add(1)
			cancelAsync = true
			swappedAny = true
			p.recordSwapLocked(train.SlotPrimary, "auto_reload", ps.BaseModel, ps.AdapterPath, ps.JobID, curModel, curAdapter, false, manifest.Previous, manifest.PreviousEscalation, ps)
		}
	} else if !hasPrimary && manifest.Previous != nil && p.triageClient != nil && p.triageClient.AdapterPath() != "" {
		curModel := p.triageClient.BaseModel()
		curAdapter := p.triageClient.AdapterPath()
		p.triageClient.ResetAdapter()
		p.adapterEpoch.Add(1)
		cancelAsync = true
		swappedAny = true
		p.recordSwapLocked(train.SlotPrimary, "auto_reload", curModel, "", "", curModel, curAdapter, false, manifest.Previous, manifest.PreviousEscalation, train.AdapterSlot{})
	}
	if manifest.Escalation != nil && p.escalationClient != nil {
		es := *manifest.Escalation
		curModel := p.escalationClient.BaseModel()
		curAdapter := p.escalationClient.AdapterPath()
		if curModel != es.BaseModel || curAdapter != es.AdapterPath {
			if err := p.escalationClient.SetModelAndAdapter(es.BaseModel, es.AdapterPath); err != nil {
				return false, err
			}
			p.escalationEpoch.Add(1)
			cancelAsync = true
			swappedAny = true
			p.recordSwapLocked(train.SlotEscalation, "auto_reload", es.BaseModel, es.AdapterPath, es.JobID, curModel, curAdapter, false, manifest.Previous, manifest.PreviousEscalation, es)
		}
	} else if manifest.Escalation == nil && manifest.PreviousEscalation != nil && p.escalationClient != nil && p.escalationClient.AdapterPath() != "" {
		curModel := p.escalationClient.BaseModel()
		curAdapter := p.escalationClient.AdapterPath()
		p.escalationClient.ResetAdapter()
		p.escalationEpoch.Add(1)
		cancelAsync = true
		swappedAny = true
		p.recordSwapLocked(train.SlotEscalation, "auto_reload", curModel, "", "", curModel, curAdapter, false, manifest.Previous, manifest.PreviousEscalation, train.AdapterSlot{})
	}

	if cancelAsync {
		p.asyncMu.Lock()
		if p.activeAsyncCancel != nil {
			p.activeAsyncCancel()
		}
		p.asyncMu.Unlock()
	}

	p.adapterMu.Lock()
	p.lastSyncedManifest = curHash
	p.hasSyncedManifest = true
	p.adapterMu.Unlock()
	return swappedAny, nil
}

func (p *Pipeline) recordSwapLocked(
	slot, action, baseModel, adapterPath, jobID, prevModel, prevAdapter string,
	verified bool,
	diskPrevPrimary, diskPrevEsc *train.AdapterSlot,
	newSlotMeta train.AdapterSlot,
) {
	now := time.Now().UTC()
	p.adapterSwapsTotal.Add(1)
	p.lastAdapterSwapUnix.Store(now.Unix())

	p.adapterMu.Lock()
	defer p.adapterMu.Unlock()

	if slot == train.SlotPrimary || slot == train.SlotAll {
		p.primaryMeta.jobID = newSlotMeta.JobID
		p.primaryMeta.datasetHash = newSlotMeta.DatasetHash
		if !newSlotMeta.ActivatedAt.IsZero() {
			p.primaryMeta.swappedAt = newSlotMeta.ActivatedAt
		} else if action != train.ActionDeactivate {
			p.primaryMeta.swappedAt = now
		} else {
			p.primaryMeta.swappedAt = time.Time{}
		}
		if diskPrevPrimary != nil {
			cp := *diskPrevPrimary
			p.primaryMeta.previous = &cp
		} else if prevAdapter != "" && prevAdapter != adapterPath {
			p.primaryMeta.previous = &train.AdapterSlot{
				BaseModel:   prevModel,
				AdapterPath: prevAdapter,
				ActivatedAt: now,
			}
		}
	}
	if slot == train.SlotEscalation || slot == train.SlotAll {
		p.escalationMeta.jobID = newSlotMeta.JobID
		p.escalationMeta.datasetHash = newSlotMeta.DatasetHash
		if !newSlotMeta.ActivatedAt.IsZero() {
			p.escalationMeta.swappedAt = newSlotMeta.ActivatedAt
		} else if action != train.ActionDeactivate {
			p.escalationMeta.swappedAt = now
		} else {
			p.escalationMeta.swappedAt = time.Time{}
		}
		if diskPrevEsc != nil {
			cp := *diskPrevEsc
			p.escalationMeta.previous = &cp
		} else if prevAdapter != "" && prevAdapter != adapterPath {
			p.escalationMeta.previous = &train.AdapterSlot{
				BaseModel:   prevModel,
				AdapterPath: prevAdapter,
				ActivatedAt: now,
			}
		}
	}

	rec := train.AdapterSwapRecord{
		Slot:                slot,
		Action:              action,
		BaseModel:           baseModel,
		AdapterPath:         adapterPath,
		JobID:               jobID,
		PreviousBaseModel:   prevModel,
		PreviousAdapterPath: prevAdapter,
		Verified:            verified,
		SwappedAt:           now,
	}
	p.adapterHistory = append(p.adapterHistory, rec)
	if len(p.adapterHistory) > maxAdapterSwapHistory {
		p.adapterHistory = append([]train.AdapterSwapRecord(nil), p.adapterHistory[len(p.adapterHistory)-maxAdapterSwapHistory:]...)
	}
}

func (p *Pipeline) snapshotSlotStatusLocked(slot string) *train.SlotStatus {
	var (
		client *triage.Client
		mode   string
		url    string
		bm     string
		meta   slotRuntimeMeta
	)
	p.adapterMu.Lock()
	if slot == train.SlotEscalation {
		meta = p.escalationMeta
		client = p.escalationClient
		mode = p.cfg.EscalationMode
		bm = p.cfg.EscalationBaseModel
	} else {
		meta = p.primaryMeta
		client = p.triageClient
		mode = p.cfg.TriageMode
		bm = p.cfg.BaseModel
	}
	p.adapterMu.Unlock()

	var adapterPath, jobID, datasetHash string
	enabled := client != nil
	if client != nil {
		mode = "http"
		bm = client.BaseModel()
		adapterPath = client.AdapterPath()
		url = client.RedactedURL()
		jobID = meta.jobID
		datasetHash = meta.datasetHash
	}
	st := &train.SlotStatus{
		Slot:         slot,
		Mode:         mode,
		Enabled:      enabled,
		BaseModel:    bm,
		AdapterPath:  adapterPath,
		JobID:        jobID,
		DatasetHash:  datasetHash,
		InferenceURL: url,
		SwappedAt:    meta.swappedAt,
	}
	if meta.previous != nil {
		st.HasRollback = true
		st.PreviousBaseModel = meta.previous.BaseModel
		st.PreviousAdapterPath = meta.previous.AdapterPath
	}
	return st
}

func (p *Pipeline) buildAdapterStatusResponseLocked(statusLabel, slot, action string, verified bool, health triage.HealthStatus) train.AdapterStatusResponse {
	respDataDir := p.cfg.DataDir
	if strings.TrimSpace(respDataDir) != "" {
		if absDir, err := filepath.Abs(respDataDir); err == nil {
			respDataDir = absDir
		}
	}
	primary := p.snapshotSlotStatusLocked(train.SlotPrimary)
	escalation := p.snapshotSlotStatusLocked(train.SlotEscalation)

	p.adapterMu.Lock()
	histCopy := make([]train.AdapterSwapRecord, len(p.adapterHistory))
	copy(histCopy, p.adapterHistory)
	p.adapterMu.Unlock()

	var activeBM, activeAdapter, activeJob string
	if slot == train.SlotEscalation {
		activeBM = escalation.BaseModel
		activeAdapter = escalation.AdapterPath
		activeJob = escalation.JobID
	} else {
		activeBM = primary.BaseModel
		activeAdapter = primary.AdapterPath
		activeJob = primary.JobID
	}
	return train.AdapterStatusResponse{
		Status:            statusLabel,
		Slot:              slot,
		Action:            action,
		JobID:             activeJob,
		BaseModel:         activeBM,
		AdapterPath:       activeAdapter,
		DataDir:           respDataDir,
		TriageEnabled:     p.triageClient != nil,
		EscalationEnabled: p.escalationClient != nil,
		Verified:          verified,
		HealthStatus:      health.Status,
		HealthBaseModel:   health.BaseModel,
		HealthBackend:     health.Backend,
		Primary:           primary,
		Escalation:        escalation,
		AdapterSwapsTotal: p.adapterSwapsTotal.Load(),
		RecentSwaps:       histCopy,
	}
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (p *Pipeline) handleAdapterRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		p.burnMu.RLock()
		defer p.burnMu.RUnlock()
		_ = json.NewEncoder(w).Encode(p.buildAdapterStatusResponseLocked("ok", "", "", false, triage.HealthStatus{}))
		return

	case http.MethodDelete:
		rawSlot := r.URL.Query().Get("slot")
		slot, err := train.NormalizeSlot(rawSlot, true)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		p.handleAdapterDeactivate(w, slot)
		return

	case http.MethodPost:
		// Require application/json Content-Type so cross-origin browser simple POSTs (text/plain,
		// form-urlencoded) cannot trigger state mutation even when loopback auth_token is unset.
		mediaType, _, mtErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mtErr != nil || mediaType != "application/json" {
			writeJSONError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
			return
		}
		var req train.AdapterSwapRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
		if err := dec.Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON payload")
			return
		}
		var trailing any
		if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
			writeJSONError(w, http.StatusBadRequest, "invalid JSON payload: unexpected trailing data")
			return
		}

		action := strings.ToLower(strings.TrimSpace(req.Action))
		if action == "" {
			action = train.ActionActivate
		}
		switch action {
		case train.ActionActivate, train.ActionRollback, train.ActionDeactivate:
		default:
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid adapter action %q: must be activate, rollback, or deactivate", req.Action))
			return
		}

		slot, err := train.NormalizeSlot(req.Slot, action == train.ActionDeactivate)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if action == train.ActionDeactivate {
			p.handleAdapterDeactivate(w, slot)
			return
		}
		if action == train.ActionRollback {
			p.handleAdapterRollback(w, r, slot, req.Verify, req.Enable)
			return
		}
		p.handleAdapterActivate(w, r, slot, req)

	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed; use GET, POST, or DELETE")
	}
}

func (p *Pipeline) prepareVerifyClient(slot, baseModel string, allowEnable bool) (*triage.Client, time.Duration, error) {
	p.burnMu.RLock()
	var existing *triage.Client
	var baseURL string
	var timeoutSec, maxTokens int
	var temp float64
	if slot == train.SlotEscalation {
		existing = p.escalationClient
		baseURL = p.cfg.EscalationInferenceAddr
		timeoutSec = p.cfg.EscalationTimeoutSec
		maxTokens = p.cfg.EscalationMaxTokens
		temp = p.cfg.TriageTemperature
	} else {
		existing = p.triageClient
		baseURL = p.cfg.InferenceAddr
		timeoutSec = p.cfg.TriageTimeoutSec
		maxTokens = p.cfg.TriageMaxTokens
		temp = p.cfg.TriageTemperature
	}
	p.burnMu.RUnlock()

	if existing != nil {
		return existing, 0, nil
	}
	if !allowEnable {
		return nil, 0, fmt.Errorf("cannot verify %s slot while %s inference is off (pass enable=true to verify and enable)", slot, slot)
	}
	return buildSlotClient(baseURL, baseModel, "", p.cfg.FTaaSAPIKey, timeoutSec, maxTokens, temp, p.cfg.MaxPromptByte, p.cfg.AllowRemoteEndpoints)
}

func (p *Pipeline) enableSlotClientLocked(slot, baseModel, adapterPath string) error {
	if slot == train.SlotEscalation {
		tc, reqTimeout, err := buildSlotClient(
			p.cfg.EscalationInferenceAddr, baseModel, adapterPath, p.cfg.FTaaSAPIKey,
			p.cfg.EscalationTimeoutSec, p.cfg.EscalationMaxTokens, p.cfg.TriageTemperature,
			p.cfg.MaxPromptByte, p.cfg.AllowRemoteEndpoints,
		)
		if err != nil {
			return err
		}
		p.escalationClient = tc
		p.escalationTimeout = reqTimeout
		return nil
	}
	tc, reqTimeout, err := buildSlotClient(
		p.cfg.InferenceAddr, baseModel, adapterPath, p.cfg.FTaaSAPIKey,
		p.cfg.TriageTimeoutSec, p.cfg.TriageMaxTokens, p.cfg.TriageTemperature,
		p.cfg.MaxPromptByte, p.cfg.AllowRemoteEndpoints,
	)
	if err != nil {
		return err
	}
	p.triageClient = tc
	p.triageReqTimeout = reqTimeout
	return nil
}

func (p *Pipeline) handleAdapterActivate(w http.ResponseWriter, r *http.Request, slot string, req train.AdapterSwapRequest) {
	baseModel := strings.TrimSpace(req.BaseModel)
	if baseModel == "" {
		if slot == train.SlotEscalation {
			baseModel = p.cfg.EscalationBaseModel
		} else {
			baseModel = p.cfg.BaseModel
		}
	}
	if _, err := model.ValidateBaseModel(baseModel); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	cleanAdapter, err := model.ValidateAdapterPath(req.AdapterPath)
	if err != nil || cleanAdapter == "" {
		msg := "adapter_path is required"
		if err != nil {
			msg = err.Error()
		}
		writeJSONError(w, http.StatusBadRequest, msg)
		return
	}

	var health triage.HealthStatus
	if req.Verify {
		vc, _, vcErr := p.prepareVerifyClient(slot, baseModel, req.Enable)
		if vcErr != nil {
			writeJSONError(w, http.StatusBadRequest, vcErr.Error())
			return
		}
		verifyCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		st, hErr := vc.VerifyHealth(verifyCtx, baseModel)
		cancel()
		if hErr != nil {
			code := http.StatusServiceUnavailable
			if strings.Contains(hErr.Error(), "serves ") {
				code = http.StatusConflict
			}
			writeJSONError(w, code, fmt.Sprintf("adapter preflight verification failed: %v", hErr))
			return
		}
		health = st
	}

	p.burnMu.Lock()
	defer p.burnMu.Unlock()

	slotState := train.AdapterSlot{
		JobID:       strings.TrimSpace(req.JobID),
		BaseModel:   baseModel,
		AdapterPath: cleanAdapter,
		DatasetHash: strings.TrimSpace(req.DatasetHash),
		ActivatedAt: time.Now().UTC(),
	}

	var diskManifest train.ActiveAdapter
	if p.cfg.DataDir != "" {
		var saveErr error
		diskManifest, saveErr = train.UpdateActiveAdapterSlot(p.cfg.DataDir, slot, slotState)
		if saveErr != nil {
			writeJSONError(w, http.StatusInternalServerError, saveErr.Error())
			return
		}
	}

	var prevModel, prevAdapter string
	if slot == train.SlotEscalation {
		if p.escalationClient == nil && req.Enable {
			if err := p.enableSlotClientLocked(slot, baseModel, cleanAdapter); err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
		} else if p.escalationClient != nil {
			prevModel = p.escalationClient.BaseModel()
			prevAdapter = p.escalationClient.AdapterPath()
			if err := p.escalationClient.SetModelAndAdapter(baseModel, cleanAdapter); err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		p.escalationEpoch.Add(1)
	} else {
		if p.triageClient == nil && req.Enable {
			if err := p.enableSlotClientLocked(slot, baseModel, cleanAdapter); err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
		} else if p.triageClient != nil {
			prevModel = p.triageClient.BaseModel()
			prevAdapter = p.triageClient.AdapterPath()
			if err := p.triageClient.SetModelAndAdapter(baseModel, cleanAdapter); err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		p.adapterEpoch.Add(1)
	}

	p.asyncMu.Lock()
	if p.activeAsyncCancel != nil {
		p.activeAsyncCancel()
	}
	p.asyncMu.Unlock()

	p.recordSwapLocked(slot, train.ActionActivate, baseModel, cleanAdapter, slotState.JobID, prevModel, prevAdapter, req.Verify, diskManifest.Previous, diskManifest.PreviousEscalation, slotState)
	if p.cfg.DataDir != "" {
		p.refreshSyncedManifestHashLocked()
	}

	_ = json.NewEncoder(w).Encode(p.buildAdapterStatusResponseLocked("activated", slot, train.ActionActivate, req.Verify, health))
}

func (p *Pipeline) handleAdapterRollback(w http.ResponseWriter, r *http.Request, slot string, verify, enable bool) {
	// Resolve target rollback candidate under RLock so optional VerifyHealth does not hold burnMu.Lock.
	p.burnMu.RLock()
	var candidate *train.AdapterSlot
	p.adapterMu.Lock()
	if slot == train.SlotEscalation {
		if p.escalationMeta.previous != nil {
			cp := *p.escalationMeta.previous
			candidate = &cp
		}
	} else {
		if p.primaryMeta.previous != nil {
			cp := *p.primaryMeta.previous
			candidate = &cp
		}
	}
	p.adapterMu.Unlock()
	if candidate == nil && p.cfg.DataDir != "" {
		if manifest, exists, err := train.LoadActiveAdapter(p.cfg.DataDir); err == nil && exists {
			if slot == train.SlotEscalation && manifest.PreviousEscalation != nil {
				cp := *manifest.PreviousEscalation
				candidate = &cp
			} else if slot == train.SlotPrimary && manifest.Previous != nil {
				cp := *manifest.Previous
				candidate = &cp
			}
		}
	}
	p.burnMu.RUnlock()

	if candidate == nil {
		writeJSONError(w, http.StatusConflict, train.ErrNoRollbackAvailable.Error())
		return
	}

	var health triage.HealthStatus
	if verify {
		vc, _, vcErr := p.prepareVerifyClient(slot, candidate.BaseModel, enable)
		if vcErr != nil {
			writeJSONError(w, http.StatusBadRequest, vcErr.Error())
			return
		}
		verifyCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		st, hErr := vc.VerifyHealth(verifyCtx, candidate.BaseModel)
		cancel()
		if hErr != nil {
			code := http.StatusServiceUnavailable
			if strings.Contains(hErr.Error(), "serves ") {
				code = http.StatusConflict
			}
			writeJSONError(w, code, fmt.Sprintf("rollback preflight verification failed: %v", hErr))
			return
		}
		health = st
	}

	p.burnMu.Lock()
	defer p.burnMu.Unlock()

	var (
		diskManifest train.ActiveAdapter
		restored     train.AdapterSlot
	)
	if p.cfg.DataDir != "" {
		var err error
		diskManifest, restored, err = train.RollbackActiveAdapterSlot(p.cfg.DataDir, slot)
		if errors.Is(err, train.ErrNoRollbackAvailable) {
			writeJSONError(w, http.StatusConflict, err.Error())
			return
		}
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else {
		p.adapterMu.Lock()
		if slot == train.SlotEscalation {
			if p.escalationMeta.previous == nil {
				p.adapterMu.Unlock()
				writeJSONError(w, http.StatusConflict, train.ErrNoRollbackAvailable.Error())
				return
			}
			restored = *p.escalationMeta.previous
			if p.escalationClient != nil && p.escalationClient.AdapterPath() != "" {
				p.escalationMeta.previous = &train.AdapterSlot{
					JobID:       p.escalationMeta.jobID,
					BaseModel:   p.escalationClient.BaseModel(),
					AdapterPath: p.escalationClient.AdapterPath(),
					DatasetHash: p.escalationMeta.datasetHash,
					ActivatedAt: p.escalationMeta.swappedAt,
				}
			} else {
				p.escalationMeta.previous = nil
			}
		} else {
			if p.primaryMeta.previous == nil {
				p.adapterMu.Unlock()
				writeJSONError(w, http.StatusConflict, train.ErrNoRollbackAvailable.Error())
				return
			}
			restored = *p.primaryMeta.previous
			if p.triageClient != nil && p.triageClient.AdapterPath() != "" {
				p.primaryMeta.previous = &train.AdapterSlot{
					JobID:       p.primaryMeta.jobID,
					BaseModel:   p.triageClient.BaseModel(),
					AdapterPath: p.triageClient.AdapterPath(),
					DatasetHash: p.primaryMeta.datasetHash,
					ActivatedAt: p.primaryMeta.swappedAt,
				}
			} else {
				p.primaryMeta.previous = nil
			}
		}
		p.adapterMu.Unlock()
	}

	var prevModel, prevAdapter string
	if slot == train.SlotEscalation {
		if p.escalationClient == nil && enable {
			if err := p.enableSlotClientLocked(slot, restored.BaseModel, restored.AdapterPath); err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
		} else if p.escalationClient != nil {
			prevModel = p.escalationClient.BaseModel()
			prevAdapter = p.escalationClient.AdapterPath()
			if err := p.escalationClient.SetModelAndAdapter(restored.BaseModel, restored.AdapterPath); err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		p.escalationEpoch.Add(1)
	} else {
		if p.triageClient == nil && enable {
			if err := p.enableSlotClientLocked(slot, restored.BaseModel, restored.AdapterPath); err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
		} else if p.triageClient != nil {
			prevModel = p.triageClient.BaseModel()
			prevAdapter = p.triageClient.AdapterPath()
			if err := p.triageClient.SetModelAndAdapter(restored.BaseModel, restored.AdapterPath); err != nil {
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		p.adapterEpoch.Add(1)
	}

	p.asyncMu.Lock()
	if p.activeAsyncCancel != nil {
		p.activeAsyncCancel()
	}
	p.asyncMu.Unlock()

	p.recordSwapLocked(slot, train.ActionRollback, restored.BaseModel, restored.AdapterPath, restored.JobID, prevModel, prevAdapter, verify, diskManifest.Previous, diskManifest.PreviousEscalation, restored)
	if p.cfg.DataDir != "" {
		p.refreshSyncedManifestHashLocked()
	}
	_ = json.NewEncoder(w).Encode(p.buildAdapterStatusResponseLocked("rolled_back", slot, train.ActionRollback, verify, health))
}

func (p *Pipeline) handleAdapterDeactivate(w http.ResponseWriter, slot string) {
	p.burnMu.Lock()
	defer p.burnMu.Unlock()

	var diskManifest train.ActiveAdapter
	if p.cfg.DataDir != "" {
		var err error
		diskManifest, _, err = train.DeactivateActiveAdapterSlot(p.cfg.DataDir, slot)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	var prevModel, prevAdapter string
	if slot == train.SlotPrimary || slot == train.SlotAll {
		if p.triageClient != nil {
			prevModel = p.triageClient.BaseModel()
			prevAdapter = p.triageClient.AdapterPath()
			p.triageClient.ResetAdapter()
		}
		p.adapterEpoch.Add(1)
		p.recordSwapLocked(train.SlotPrimary, train.ActionDeactivate, prevModel, "", "", prevModel, prevAdapter, false, diskManifest.Previous, diskManifest.PreviousEscalation, train.AdapterSlot{})
	}
	if slot == train.SlotEscalation || slot == train.SlotAll {
		var escPrevModel, escPrevAdapter string
		if p.escalationClient != nil {
			escPrevModel = p.escalationClient.BaseModel()
			escPrevAdapter = p.escalationClient.AdapterPath()
			p.escalationClient.ResetAdapter()
		}
		p.escalationEpoch.Add(1)
		p.recordSwapLocked(train.SlotEscalation, train.ActionDeactivate, escPrevModel, "", "", escPrevModel, escPrevAdapter, false, diskManifest.Previous, diskManifest.PreviousEscalation, train.AdapterSlot{})
	}

	p.asyncMu.Lock()
	if p.activeAsyncCancel != nil {
		p.activeAsyncCancel()
	}
	p.asyncMu.Unlock()

	if p.cfg.DataDir != "" {
		p.refreshSyncedManifestHashLocked()
	}
	_ = json.NewEncoder(w).Encode(p.buildAdapterStatusResponseLocked("deactivated", slot, train.ActionDeactivate, false, triage.HealthStatus{}))
}
