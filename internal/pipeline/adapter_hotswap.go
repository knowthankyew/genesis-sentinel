package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
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
	maxSwapAuditFieldBytes   = 128
)

type correlationEntry struct {
	timestamp     int64
	alertSeq      uint64
	templateID    string
	severity      string
	category      string
	count         uint64
	surprisalNats float64
	triageClass   string
}

type slotRuntimeMeta struct {
	baseModel   string
	adapterPath string
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

func cloneSlotPtr(s *train.AdapterSlot) *train.AdapterSlot {
	if s == nil {
		return nil
	}
	cp := *s
	return &cp
}

func slotsEqual(a, b train.AdapterSlot) bool {
	return a.BaseModel == b.BaseModel && a.AdapterPath == b.AdapterPath && a.JobID == b.JobID
}

func clientMatchesDiskSlot(client *triage.Client, slot *train.AdapterSlot) bool {
	if client == nil || slot == nil {
		return true
	}
	return client.BaseModel() == slot.BaseModel && client.AdapterPath() == slot.AdapterPath
}

func (p *Pipeline) initAdapterTracking() {
	if p.cfg.DataDir == "" {
		return
	}
	manifest, hash, exists, loadErr := train.LoadActiveAdapterWithHash(p.cfg.DataDir)
	if loadErr != nil || !exists {
		return
	}
	p.adapterMu.Lock()
	var psPtr *train.AdapterSlot
	if ps, ok := manifest.PrimarySlot(); ok {
		psPtr = &ps
		if p.triageClient == nil || ps.AdapterPath == p.cfg.AdapterPath {
			p.primaryMeta.baseModel = ps.BaseModel
			p.primaryMeta.adapterPath = ps.AdapterPath
			p.primaryMeta.jobID = ps.JobID
			p.primaryMeta.datasetHash = ps.DatasetHash
			p.primaryMeta.swappedAt = ps.ActivatedAt
		}
	}
	p.primaryMeta.previous = cloneSlotPtr(manifest.Previous)
	if manifest.Escalation != nil && (p.escalationClient == nil || manifest.Escalation.AdapterPath == p.cfg.EscalationAdapterPath) {
		p.escalationMeta.baseModel = manifest.Escalation.BaseModel
		p.escalationMeta.adapterPath = manifest.Escalation.AdapterPath
		p.escalationMeta.jobID = manifest.Escalation.JobID
		p.escalationMeta.datasetHash = manifest.Escalation.DatasetHash
		p.escalationMeta.swappedAt = manifest.Escalation.ActivatedAt
	}
	p.escalationMeta.previous = cloneSlotPtr(manifest.PreviousEscalation)
	if clientMatchesDiskSlot(p.triageClient, psPtr) && clientMatchesDiskSlot(p.escalationClient, manifest.Escalation) {
		p.lastSyncedManifest = hash
		p.hasSyncedManifest = true
	}
	p.adapterMu.Unlock()
}

// SetInitialSyncedManifestHash records the SHA-256 of the active-adapter.json revision
// read by startup configuration (`watch`) so subsequent disk polling detects any external
// manifest replacement that occurred between startup read and pipeline construction.
func (p *Pipeline) SetInitialSyncedManifestHash(hash [sha256.Size]byte) {
	p.burnMu.Lock()
	p.adapterMu.Lock()
	p.lastSyncedManifest = hash
	p.hasSyncedManifest = true
	p.adapterMu.Unlock()
	p.burnMu.Unlock()
}

func (p *Pipeline) setSyncedManifestHashLocked(hash [sha256.Size]byte, hasFile bool) {
	p.adapterMu.Lock()
	p.lastSyncedManifest = hash
	p.hasSyncedManifest = hasFile
	p.adapterMu.Unlock()
}

func correlationServiceKeyFromHash(h [sha256.Size]byte) string {
	return hex.EncodeToString(h[:])
}

func correlationServiceKey(service string) string {
	svc := strings.TrimSpace(service)
	if svc == "" || strings.EqualFold(svc, emit.ReservedAlertService) {
		return ""
	}
	h := sha256.Sum256([]byte(svc))
	return correlationServiceKeyFromHash(h)
}

func sanitizeCorrelationTag(raw, fallback string) string {
	clean, _ := security.SanitizeUntrustedLogText(strings.TrimSpace(raw), 64)
	clean = strings.NewReplacer("\r", " ", "\n", " ", "\t", " ", "\u2028", " ", "\u2029", " ").Replace(clean)
	clean = strings.TrimSpace(clean)
	if clean == "" {
		return fallback
	}
	return clean
}

// collectCorrelatedContext returns formatted compact summaries of distinct recent prior windows
// observed on the same SourceService within correlationWindowTTLSec.
func (p *Pipeline) collectCorrelatedContext(service, excludeTemplateID string, nowUnix int64) []string {
	corrKey := correlationServiceKey(service)
	if corrKey == "" {
		return nil
	}
	return p.collectCorrelatedContextByKey(corrKey, excludeTemplateID, nowUnix)
}

func (p *Pipeline) collectCorrelatedContextByKey(corrKey, excludeTemplateID string, nowUnix int64) []string {
	if corrKey == "" {
		return nil
	}
	p.corrMu.Lock()
	defer p.corrMu.Unlock()

	if len(p.serviceCorrelator) == 0 {
		return nil
	}
	entries := p.serviceCorrelator[corrKey]
	if len(entries) == 0 {
		return nil
	}

	// Compact expired entries strictly in forward index order so slice aliasing cannot
	// overwrite unread elements.
	kept := entries[:0]
	for _, e := range entries {
		age := nowUnix - e.timestamp
		if age > correlationWindowTTLSec || age < -correlationWindowTTLSec {
			continue
		}
		kept = append(kept, e)
	}
	if len(kept) == 0 {
		delete(p.serviceCorrelator, corrKey)
		return nil
	}
	p.serviceCorrelator[corrKey] = kept

	out := make([]string, 0, maxCorrelationPerService)
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
		tag = sanitizeCorrelationTag(tag, "anomaly")
		sev := sanitizeCorrelationTag(e.severity, "MEDIUM")
		summary := fmt.Sprintf("%s(%s,%s,cnt=%d)", tidShort, tag, sev, e.count)
		out = append(out, summary)
	}
	return out
}

func (p *Pipeline) recordCorrelationWindow(a emit.Alert) {
	corrKey := correlationServiceKey(a.SourceService)
	p.recordCorrelationWindowWithKey(corrKey, 0, a)
}

func (p *Pipeline) recordCorrelationWindowWithKey(corrKey string, alertSeq uint64, a emit.Alert) {
	svc := strings.TrimSpace(a.SourceService)
	if corrKey == "" || svc == "" || strings.EqualFold(svc, emit.ReservedAlertService) || strings.TrimSpace(a.TemplateID) == "" {
		return
	}
	cat := "surprisal"
	if len(a.Categories) > 0 && strings.TrimSpace(a.Categories[0]) != "" {
		cat = sanitizeCorrelationTag(a.Categories[0], "surprisal")
	}
	entry := correlationEntry{
		timestamp:     a.Timestamp,
		alertSeq:      alertSeq,
		templateID:    a.TemplateID,
		severity:      sanitizeCorrelationTag(a.Severity, "MEDIUM"),
		category:      cat,
		count:         a.Count,
		surprisalNats: a.SurprisalNats,
		triageClass:   sanitizeCorrelationTag(a.TriageClass, ""),
	}

	p.corrMu.Lock()
	defer p.corrMu.Unlock()
	if p.serviceCorrelator == nil {
		p.serviceCorrelator = make(map[string][]correlationEntry, 8)
	}
	if _, exists := p.serviceCorrelator[corrKey]; !exists && len(p.serviceCorrelator) >= maxCorrelationServices {
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

	list := p.serviceCorrelator[corrKey]
	for i := range list {
		if list[i].templateID == entry.templateID {
			if entry.timestamp < list[i].timestamp ||
				(entry.timestamp == list[i].timestamp && alertSeq > 0 && list[i].alertSeq > alertSeq) {
				// Never let a slower, older async enrichment overwrite a newer window entry.
				return
			}
			// Move refreshed template entry to the newest (end) position so LRU eviction preserves it.
			list = append(list[:i], list[i+1:]...)
			list = append(list, entry)
			p.serviceCorrelator[corrKey] = list
			return
		}
	}
	list = append(list, entry)
	if len(list) > maxCorrelationPerService {
		list = append([]correlationEntry(nil), list[len(list)-maxCorrelationPerService:]...)
	}
	p.serviceCorrelator[corrKey] = list
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

// escalationReason decides whether an alert escalates under p.cfg.EscalationPolicy.
// Policy filtering intentionally continues to apply even when triage_mode="off" (no primary client):
// routine MEDIUM alerts stay Tier 0+1-only under "high_critical"/"strict" unless an escalation trigger
// fires or EscalationPolicyAlways ("always") is configured.
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
	p.burnMu.RLock()
	primaryTimeout := p.triageReqTimeout
	escTimeout := p.escalationTimeout
	p.burnMu.RUnlock()
	return p.enrichWithTier2DualWithTimeouts(ctx, primaryClient, primaryTimeout, escalationClient, escTimeout, alert)
}

func (p *Pipeline) enrichWithTier2DualWithTimeouts(
	ctx context.Context,
	primaryClient *triage.Client,
	primaryTimeout time.Duration,
	escalationClient *triage.Client,
	escalationTimeout time.Duration,
	alert *emit.Alert,
) bool {
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
		primaryVerdict, primaryOverridden, primaryErr = p.invokeSlotTriage(ctx, primaryClient, primaryTimeout, in)
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
			escVerdict, escOverridden, escErr := p.invokeSlotTriage(ctx, escalationClient, escalationTimeout, in)
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

func (p *Pipeline) refreshUnchangedSlotMetaLocked(slot string, meta *train.AdapterSlot, diskPrev *train.AdapterSlot) {
	p.adapterMu.Lock()
	defer p.adapterMu.Unlock()
	target := &p.primaryMeta
	if slot == train.SlotEscalation {
		target = &p.escalationMeta
	}
	if meta != nil {
		target.baseModel = meta.BaseModel
		target.adapterPath = meta.AdapterPath
		target.jobID = meta.JobID
		target.datasetHash = meta.DatasetHash
		if !meta.ActivatedAt.IsZero() {
			target.swappedAt = meta.ActivatedAt
		}
	} else {
		target.baseModel = ""
		target.adapterPath = ""
		target.jobID = ""
		target.datasetHash = ""
		target.swappedAt = time.Time{}
	}
	target.previous = cloneSlotPtr(diskPrev)
}

// SyncActiveAdapterFromDisk reloads active-adapter.json live when edited outside /adapter
// (e.g. direct `sentinel adapter swap` without --sentinel-http), without restarting `watch`.
func (p *Pipeline) SyncActiveAdapterFromDisk() (bool, error) {
	if !p.cfg.AutoReloadAdapter || strings.TrimSpace(p.cfg.DataDir) == "" {
		return false, nil
	}

	p.burnMu.Lock()
	defer p.burnMu.Unlock()

	manifest, curHash, curExists, err := train.LoadActiveAdapterWithHash(p.cfg.DataDir)
	if err != nil {
		return false, err
	}
	if !curExists {
		p.setSyncedManifestHashLocked([sha256.Size]byte{}, false)
		return false, nil
	}

	p.adapterMu.Lock()
	unchanged := p.hasSyncedManifest && p.lastSyncedManifest == curHash
	p.adapterMu.Unlock()
	if unchanged {
		return false, nil
	}

	// Pre-validate both slot pairs before mutating either runtime client so a valid file never
	// leaves half-applied slot updates.
	ps, hasPrimary := manifest.PrimarySlot()
	if hasPrimary && p.triageClient != nil {
		if _, err := model.ValidateBaseModel(ps.BaseModel); err != nil {
			return false, err
		}
		if _, err := model.ValidateAdapterPath(ps.AdapterPath); err != nil {
			return false, err
		}
	}
	if manifest.Escalation != nil && p.escalationClient != nil {
		if _, err := model.ValidateBaseModel(manifest.Escalation.BaseModel); err != nil {
			return false, err
		}
		if _, err := model.ValidateAdapterPath(manifest.Escalation.AdapterPath); err != nil {
			return false, err
		}
	}

	swappedAny := false
	cancelAsync := false

	if hasPrimary && p.triageClient != nil {
		curModel := p.triageClient.BaseModel()
		curAdapter := p.triageClient.AdapterPath()
		if curModel != ps.BaseModel || curAdapter != ps.AdapterPath {
			if err := p.triageClient.SetModelAndAdapter(ps.BaseModel, ps.AdapterPath); err != nil {
				return false, err
			}
			p.adapterEpoch.Add(1)
			cancelAsync = true
			swappedAny = true
			p.recordSwapLocked(train.SlotPrimary, "auto_reload", ps.BaseModel, ps.AdapterPath, ps.JobID, curModel, curAdapter, false, true, manifest.Previous, manifest.PreviousEscalation, ps)
		} else {
			p.refreshUnchangedSlotMetaLocked(train.SlotPrimary, &ps, manifest.Previous)
		}
	} else if !hasPrimary && p.triageClient != nil {
		if manifest.Previous != nil && p.triageClient.AdapterPath() != "" {
			curModel := p.triageClient.BaseModel()
			curAdapter := p.triageClient.AdapterPath()
			p.triageClient.ResetAdapter()
			p.adapterEpoch.Add(1)
			cancelAsync = true
			swappedAny = true
			p.recordSwapLocked(train.SlotPrimary, "auto_reload", curModel, "", "", curModel, curAdapter, false, true, manifest.Previous, manifest.PreviousEscalation, train.AdapterSlot{})
		} else {
			p.refreshUnchangedSlotMetaLocked(train.SlotPrimary, nil, manifest.Previous)
		}
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
			p.recordSwapLocked(train.SlotEscalation, "auto_reload", es.BaseModel, es.AdapterPath, es.JobID, curModel, curAdapter, false, true, manifest.Previous, manifest.PreviousEscalation, es)
		} else {
			p.refreshUnchangedSlotMetaLocked(train.SlotEscalation, &es, manifest.PreviousEscalation)
		}
	} else if manifest.Escalation == nil && p.escalationClient != nil {
		if manifest.PreviousEscalation != nil && p.escalationClient.AdapterPath() != "" {
			curModel := p.escalationClient.BaseModel()
			curAdapter := p.escalationClient.AdapterPath()
			p.escalationClient.ResetAdapter()
			p.escalationEpoch.Add(1)
			cancelAsync = true
			swappedAny = true
			p.recordSwapLocked(train.SlotEscalation, "auto_reload", curModel, "", "", curModel, curAdapter, false, true, manifest.Previous, manifest.PreviousEscalation, train.AdapterSlot{})
		} else {
			p.refreshUnchangedSlotMetaLocked(train.SlotEscalation, nil, manifest.PreviousEscalation)
		}
	}

	if cancelAsync {
		p.asyncMu.Lock()
		if p.activeAsyncCancel != nil {
			p.activeAsyncCancel()
		}
		p.asyncMu.Unlock()
	}

	p.setSyncedManifestHashLocked(curHash, true)
	return swappedAny, nil
}

func truncateAuditField(s string, maxBytes int) string {
	s = strings.TrimSpace(s)
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	return truncateSummary(s, maxBytes)
}

func (p *Pipeline) recordSwapLocked(
	slot, action, baseModel, adapterPath, jobID, prevModel, prevAdapter string,
	verified bool,
	hasDiskManifest bool,
	diskPrevPrimary, diskPrevEsc *train.AdapterSlot,
	newSlotMeta train.AdapterSlot,
) {
	now := time.Now().UTC()
	p.adapterSwapsTotal.Add(1)
	p.lastAdapterSwapUnix.Store(now.Unix())

	p.adapterMu.Lock()
	defer p.adapterMu.Unlock()

	if slot == train.SlotPrimary || slot == train.SlotAll {
		p.primaryMeta.baseModel = baseModel
		p.primaryMeta.adapterPath = adapterPath
		p.primaryMeta.jobID = newSlotMeta.JobID
		p.primaryMeta.datasetHash = newSlotMeta.DatasetHash
		if !newSlotMeta.ActivatedAt.IsZero() {
			p.primaryMeta.swappedAt = newSlotMeta.ActivatedAt
		} else if action != train.ActionDeactivate {
			p.primaryMeta.swappedAt = now
		} else {
			p.primaryMeta.swappedAt = time.Time{}
		}
		if hasDiskManifest {
			p.primaryMeta.previous = cloneSlotPtr(diskPrevPrimary)
		} else if prevAdapter != "" && prevAdapter != adapterPath {
			p.primaryMeta.previous = &train.AdapterSlot{
				BaseModel:   prevModel,
				AdapterPath: prevAdapter,
				ActivatedAt: now,
			}
		}
	}
	if slot == train.SlotEscalation || slot == train.SlotAll {
		p.escalationMeta.baseModel = baseModel
		p.escalationMeta.adapterPath = adapterPath
		p.escalationMeta.jobID = newSlotMeta.JobID
		p.escalationMeta.datasetHash = newSlotMeta.DatasetHash
		if !newSlotMeta.ActivatedAt.IsZero() {
			p.escalationMeta.swappedAt = newSlotMeta.ActivatedAt
		} else if action != train.ActionDeactivate {
			p.escalationMeta.swappedAt = now
		} else {
			p.escalationMeta.swappedAt = time.Time{}
		}
		if hasDiskManifest {
			p.escalationMeta.previous = cloneSlotPtr(diskPrevEsc)
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
		BaseModel:           truncateAuditField(baseModel, maxSwapAuditFieldBytes),
		AdapterPath:         truncateAuditField(adapterPath, maxSwapAuditFieldBytes*2),
		JobID:               truncateAuditField(jobID, maxSwapAuditFieldBytes),
		PreviousBaseModel:   truncateAuditField(prevModel, maxSwapAuditFieldBytes),
		PreviousAdapterPath: truncateAuditField(prevAdapter, maxSwapAuditFieldBytes*2),
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
	} else {
		if meta.baseModel != "" {
			bm = meta.baseModel
		}
		adapterPath = meta.adapterPath
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
	resp := train.AdapterStatusResponse{
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
	for len(resp.RecentSwaps) > 0 {
		raw, err := json.Marshal(resp)
		if err != nil || len(raw) <= train.MaxAdapterResponseBytes {
			break
		}
		resp.RecentSwaps = resp.RecentSwaps[1:]
	}
	if len(resp.RecentSwaps) == 0 {
		resp.RecentSwaps = nil
	}
	return resp
}

func writeJSONResponse(w http.ResponseWriter, code int, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"failed to marshal response"}` + "\n"))
		return
	}
	w.WriteHeader(code)
	_, _ = w.Write(append(raw, '\n'))
}

func writeJSONError(w http.ResponseWriter, code int, msg string) {
	writeJSONResponse(w, code, map[string]string{"error": msg})
}

func (p *Pipeline) handleAdapterRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.Method {
	case http.MethodGet:
		p.burnMu.RLock()
		resp := p.buildAdapterStatusResponseLocked("ok", "", "", false, triage.HealthStatus{})
		p.burnMu.RUnlock()
		writeJSONResponse(w, http.StatusOK, resp)
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

func (p *Pipeline) slotClientConfig(slot string) (existing *triage.Client, baseURL string, timeoutSec, maxTokens int, temp float64) {
	if slot == train.SlotEscalation {
		return p.escalationClient, p.cfg.EscalationInferenceAddr, p.cfg.EscalationTimeoutSec, p.cfg.EscalationMaxTokens, p.cfg.TriageTemperature
	}
	return p.triageClient, p.cfg.InferenceAddr, p.cfg.TriageTimeoutSec, p.cfg.TriageMaxTokens, p.cfg.TriageTemperature
}

func (p *Pipeline) prepareVerifyClient(slot, baseModel string, allowEnable bool) (*triage.Client, time.Duration, error) {
	p.burnMu.RLock()
	existing, baseURL, timeoutSec, maxTokens, temp := p.slotClientConfig(slot)
	p.burnMu.RUnlock()

	if existing != nil {
		return existing, 0, nil
	}
	if !allowEnable {
		return nil, 0, fmt.Errorf("cannot verify %s slot while %s inference is off (pass enable=true to verify and enable)", slot, slot)
	}
	return buildSlotClient(baseURL, baseModel, "", p.cfg.FTaaSAPIKey, timeoutSec, maxTokens, temp, p.cfg.MaxPromptByte, p.cfg.AllowRemoteEndpoints)
}

func (p *Pipeline) prepareEnableClient(slot, baseModel, adapterPath string) (*triage.Client, time.Duration, error) {
	p.burnMu.RLock()
	existing, baseURL, timeoutSec, maxTokens, temp := p.slotClientConfig(slot)
	p.burnMu.RUnlock()
	if existing != nil {
		return nil, 0, nil
	}
	return buildSlotClient(baseURL, baseModel, adapterPath, p.cfg.FTaaSAPIKey, timeoutSec, maxTokens, temp, p.cfg.MaxPromptByte, p.cfg.AllowRemoteEndpoints)
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

	// Prepare any dynamic slot client BEFORE mutating persisted manifest or rollback snapshots.
	var (
		preparedClient  *triage.Client
		preparedTimeout time.Duration
	)
	if req.Enable {
		var prepErr error
		preparedClient, preparedTimeout, prepErr = p.prepareEnableClient(slot, baseModel, cleanAdapter)
		if prepErr != nil {
			writeJSONError(w, http.StatusBadRequest, prepErr.Error())
			return
		}
	}

	slotState := train.AdapterSlot{
		JobID:       strings.TrimSpace(req.JobID),
		BaseModel:   baseModel,
		AdapterPath: cleanAdapter,
		DatasetHash: strings.TrimSpace(req.DatasetHash),
		ActivatedAt: time.Now().UTC(),
	}

	p.burnMu.Lock()
	var (
		diskManifest train.ActiveAdapter
		writtenHash  [sha256.Size]byte
	)
	hasDiskManifest := p.cfg.DataDir != ""
	if hasDiskManifest {
		var saveErr error
		diskManifest, writtenHash, saveErr = train.UpdateActiveAdapterSlotWithHash(p.cfg.DataDir, slot, slotState)
		if saveErr != nil {
			p.burnMu.Unlock()
			writeJSONError(w, http.StatusInternalServerError, saveErr.Error())
			return
		}
	}

	var prevModel, prevAdapter string
	if slot == train.SlotEscalation {
		if p.escalationClient == nil && req.Enable {
			if preparedClient == nil {
				var err error
				preparedClient, preparedTimeout, err = buildSlotClient(
					p.cfg.EscalationInferenceAddr, baseModel, cleanAdapter, p.cfg.FTaaSAPIKey,
					p.cfg.EscalationTimeoutSec, p.cfg.EscalationMaxTokens, p.cfg.TriageTemperature,
					p.cfg.MaxPromptByte, p.cfg.AllowRemoteEndpoints,
				)
				if err != nil {
					p.burnMu.Unlock()
					writeJSONError(w, http.StatusBadRequest, err.Error())
					return
				}
			}
			p.escalationClient = preparedClient
			p.escalationTimeout = preparedTimeout
		} else if p.escalationClient != nil {
			prevModel = p.escalationClient.BaseModel()
			prevAdapter = p.escalationClient.AdapterPath()
			if err := p.escalationClient.SetModelAndAdapter(baseModel, cleanAdapter); err != nil {
				p.burnMu.Unlock()
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		p.escalationEpoch.Add(1)
	} else {
		if p.triageClient == nil && req.Enable {
			if preparedClient == nil {
				var err error
				preparedClient, preparedTimeout, err = buildSlotClient(
					p.cfg.InferenceAddr, baseModel, cleanAdapter, p.cfg.FTaaSAPIKey,
					p.cfg.TriageTimeoutSec, p.cfg.TriageMaxTokens, p.cfg.TriageTemperature,
					p.cfg.MaxPromptByte, p.cfg.AllowRemoteEndpoints,
				)
				if err != nil {
					p.burnMu.Unlock()
					writeJSONError(w, http.StatusBadRequest, err.Error())
					return
				}
			}
			p.triageClient = preparedClient
			p.triageReqTimeout = preparedTimeout
		} else if p.triageClient != nil {
			prevModel = p.triageClient.BaseModel()
			prevAdapter = p.triageClient.AdapterPath()
			if err := p.triageClient.SetModelAndAdapter(baseModel, cleanAdapter); err != nil {
				p.burnMu.Unlock()
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

	p.recordSwapLocked(slot, train.ActionActivate, baseModel, cleanAdapter, slotState.JobID, prevModel, prevAdapter, req.Verify, hasDiskManifest, diskManifest.Previous, diskManifest.PreviousEscalation, slotState)
	if hasDiskManifest {
		p.setSyncedManifestHashLocked(writtenHash, true)
	}
	resp := p.buildAdapterStatusResponseLocked("activated", slot, train.ActionActivate, req.Verify, health)
	p.burnMu.Unlock()

	writeJSONResponse(w, http.StatusOK, resp)
}

func (p *Pipeline) handleAdapterRollback(w http.ResponseWriter, r *http.Request, slot string, verify, enable bool) {
	// Resolve target rollback candidate under RLock so optional VerifyHealth does not hold burnMu.Lock.
	p.burnMu.RLock()
	var candidate *train.AdapterSlot
	p.adapterMu.Lock()
	if slot == train.SlotEscalation {
		candidate = cloneSlotPtr(p.escalationMeta.previous)
	} else {
		candidate = cloneSlotPtr(p.primaryMeta.previous)
	}
	p.adapterMu.Unlock()
	if candidate == nil && p.cfg.DataDir != "" {
		if manifest, exists, err := train.LoadActiveAdapter(p.cfg.DataDir); err == nil && exists {
			if slot == train.SlotEscalation {
				candidate = cloneSlotPtr(manifest.PreviousEscalation)
			} else {
				candidate = cloneSlotPtr(manifest.Previous)
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

	// Prepare dynamic slot client BEFORE mutating disk manifest or rollback snapshot.
	var (
		preparedClient  *triage.Client
		preparedTimeout time.Duration
	)
	if enable {
		var prepErr error
		preparedClient, preparedTimeout, prepErr = p.prepareEnableClient(slot, candidate.BaseModel, candidate.AdapterPath)
		if prepErr != nil {
			writeJSONError(w, http.StatusBadRequest, prepErr.Error())
			return
		}
	}

	p.burnMu.Lock()
	var (
		diskManifest train.ActiveAdapter
		restored     train.AdapterSlot
		writtenHash  [sha256.Size]byte
	)
	hasDiskManifest := p.cfg.DataDir != ""
	if hasDiskManifest {
		var expected *train.AdapterSlot
		if verify {
			expected = candidate
		}
		var err error
		diskManifest, restored, writtenHash, err = train.RollbackActiveAdapterSlotExpected(p.cfg.DataDir, slot, expected)
		if errors.Is(err, train.ErrNoRollbackAvailable) || errors.Is(err, train.ErrRollbackTargetChanged) {
			p.burnMu.Unlock()
			writeJSONError(w, http.StatusConflict, err.Error())
			return
		}
		if err != nil {
			p.burnMu.Unlock()
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else {
		p.adapterMu.Lock()
		if slot == train.SlotEscalation {
			if p.escalationMeta.previous == nil {
				p.adapterMu.Unlock()
				p.burnMu.Unlock()
				writeJSONError(w, http.StatusConflict, train.ErrNoRollbackAvailable.Error())
				return
			}
			if verify && !slotsEqual(*p.escalationMeta.previous, *candidate) {
				p.adapterMu.Unlock()
				p.burnMu.Unlock()
				writeJSONError(w, http.StatusConflict, train.ErrRollbackTargetChanged.Error())
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
				p.burnMu.Unlock()
				writeJSONError(w, http.StatusConflict, train.ErrNoRollbackAvailable.Error())
				return
			}
			if verify && !slotsEqual(*p.primaryMeta.previous, *candidate) {
				p.adapterMu.Unlock()
				p.burnMu.Unlock()
				writeJSONError(w, http.StatusConflict, train.ErrRollbackTargetChanged.Error())
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
			if preparedClient == nil || !slotsEqual(restored, *candidate) {
				var err error
				preparedClient, preparedTimeout, err = buildSlotClient(
					p.cfg.EscalationInferenceAddr, restored.BaseModel, restored.AdapterPath, p.cfg.FTaaSAPIKey,
					p.cfg.EscalationTimeoutSec, p.cfg.EscalationMaxTokens, p.cfg.TriageTemperature,
					p.cfg.MaxPromptByte, p.cfg.AllowRemoteEndpoints,
				)
				if err != nil {
					p.burnMu.Unlock()
					writeJSONError(w, http.StatusBadRequest, err.Error())
					return
				}
			}
			p.escalationClient = preparedClient
			p.escalationTimeout = preparedTimeout
		} else if p.escalationClient != nil {
			prevModel = p.escalationClient.BaseModel()
			prevAdapter = p.escalationClient.AdapterPath()
			if err := p.escalationClient.SetModelAndAdapter(restored.BaseModel, restored.AdapterPath); err != nil {
				p.burnMu.Unlock()
				writeJSONError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		p.escalationEpoch.Add(1)
	} else {
		if p.triageClient == nil && enable {
			if preparedClient == nil || !slotsEqual(restored, *candidate) {
				var err error
				preparedClient, preparedTimeout, err = buildSlotClient(
					p.cfg.InferenceAddr, restored.BaseModel, restored.AdapterPath, p.cfg.FTaaSAPIKey,
					p.cfg.TriageTimeoutSec, p.cfg.TriageMaxTokens, p.cfg.TriageTemperature,
					p.cfg.MaxPromptByte, p.cfg.AllowRemoteEndpoints,
				)
				if err != nil {
					p.burnMu.Unlock()
					writeJSONError(w, http.StatusBadRequest, err.Error())
					return
				}
			}
			p.triageClient = preparedClient
			p.triageReqTimeout = preparedTimeout
		} else if p.triageClient != nil {
			prevModel = p.triageClient.BaseModel()
			prevAdapter = p.triageClient.AdapterPath()
			if err := p.triageClient.SetModelAndAdapter(restored.BaseModel, restored.AdapterPath); err != nil {
				p.burnMu.Unlock()
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

	p.recordSwapLocked(slot, train.ActionRollback, restored.BaseModel, restored.AdapterPath, restored.JobID, prevModel, prevAdapter, verify, hasDiskManifest, diskManifest.Previous, diskManifest.PreviousEscalation, restored)
	if hasDiskManifest {
		p.setSyncedManifestHashLocked(writtenHash, true)
	}
	resp := p.buildAdapterStatusResponseLocked("rolled_back", slot, train.ActionRollback, verify, health)
	p.burnMu.Unlock()

	writeJSONResponse(w, http.StatusOK, resp)
}

func (p *Pipeline) handleAdapterDeactivate(w http.ResponseWriter, slot string) {
	p.burnMu.Lock()

	var (
		diskManifest train.ActiveAdapter
		writtenHash  [sha256.Size]byte
		hasFile      bool
	)
	hasDiskManifest := p.cfg.DataDir != ""
	if hasDiskManifest {
		var err error
		diskManifest, writtenHash, _, hasFile, err = train.DeactivateActiveAdapterSlotWithHash(p.cfg.DataDir, slot)
		if err != nil {
			p.burnMu.Unlock()
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
		p.recordSwapLocked(train.SlotPrimary, train.ActionDeactivate, prevModel, "", "", prevModel, prevAdapter, false, hasDiskManifest, diskManifest.Previous, diskManifest.PreviousEscalation, train.AdapterSlot{})
	}
	if slot == train.SlotEscalation || slot == train.SlotAll {
		var escPrevModel, escPrevAdapter string
		if p.escalationClient != nil {
			escPrevModel = p.escalationClient.BaseModel()
			escPrevAdapter = p.escalationClient.AdapterPath()
			p.escalationClient.ResetAdapter()
		}
		p.escalationEpoch.Add(1)
		p.recordSwapLocked(train.SlotEscalation, train.ActionDeactivate, escPrevModel, "", "", escPrevModel, escPrevAdapter, false, hasDiskManifest, diskManifest.Previous, diskManifest.PreviousEscalation, train.AdapterSlot{})
	}

	p.asyncMu.Lock()
	if p.activeAsyncCancel != nil {
		p.activeAsyncCancel()
	}
	p.asyncMu.Unlock()

	if hasDiskManifest {
		p.setSyncedManifestHashLocked(writtenHash, hasFile)
	}
	resp := p.buildAdapterStatusResponseLocked("deactivated", slot, train.ActionDeactivate, false, triage.HealthStatus{})
	p.burnMu.Unlock()

	writeJSONResponse(w, http.StatusOK, resp)
}
