package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
	"github.com/knowthankyew/genesis-sentinel/internal/template"
)

// Rule defines a single deterministic Tier 0 detection signature, rate threshold,
// or entropy threshold loaded from JSON or the built-in starter pack.
type Rule struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"` // LOW | MEDIUM | HIGH | CRITICAL
	Description string   `json:"description"`
	Services    []string `json:"services,omitempty"`
	Levels      []string `json:"levels,omitempty"`
	Pattern     string   `json:"pattern,omitempty"`
	MinCount    uint64   `json:"min_count,omitempty"`
	MinEntropy  float64  `json:"min_entropy,omitempty"`
	MinLength   int      `json:"min_length,omitempty"`
	Enabled     bool     `json:"enabled"`
}

// Suppression silences known benign services, templates, or message patterns.
// At least one selector (Service, Template, or Pattern) is required so an empty
// suppression cannot accidentally disable all alerting.
type Suppression struct {
	ID       string `json:"id"`
	Service  string `json:"service,omitempty"`
	Template string `json:"template,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// RulePack is the JSON wire schema for custom operator rule files (`rules.json`).
type RulePack struct {
	Version      string        `json:"version"`
	Rules        []Rule        `json:"rules"`
	Suppressions []Suppression `json:"suppressions,omitempty"`
}

type compiledRule struct {
	rule     Rule
	re       *regexp.Regexp
	services map[string]struct{}
	levels   map[string]struct{}
}

type compiledSuppression struct {
	supp Suppression
	re   *regexp.Regexp
}

// Engine evaluates incoming LogEvents and collapsed Tier 0 TemplateWindows against
// precompiled RE2 rules and prompt-injection heuristics. For a fixed rule pack of
// size |R|, each regex scan runs in linear O(L) time in input length L (total O(|R| * L)).
type Engine struct {
	rules        []compiledRule
	suppressions []compiledSuppression
}

// EventRuleMatch records a single rule hit observed on a specific LogEvent at ingest time.
type EventRuleMatch struct {
	RuleHit         model.RuleHit
	MinCount        uint64
	SanitizedSample string
	Entropy         float64
}

// EventEvaluation captures per-event suppression, deterministic rule matches,
// and adversarial prompt-injection signals before events are folded into windows.
type EventEvaluation struct {
	Suppressed         bool
	Matches            []EventRuleMatch
	InjectionSuspected bool
	InjectionSignals   []string
	InjectionSample    string
}

// EvaluationResult bundles deterministic rule hits and adversarial injection signals
// for standalone evaluation of a TemplateWindow.
type EvaluationResult struct {
	Suppressed         bool
	RuleHits           []model.RuleHit
	InjectionSuspected bool
	InjectionSignals   []string
	SanitizedSample    string
	InjectionSample    string
}

// DefaultRulePack returns Sentinel's built-in Track A/B starter security rules.
func DefaultRulePack() RulePack {
	return RulePack{
		Version: "1.0",
		Rules: []Rule{
			{
				ID:          "SENT-001",
				Category:    "auth_bruteforce",
				Severity:    "HIGH",
				Description: "Repeated authentication failure burst in window",
				Pattern:     `(?i)(failed password|invalid user|authentication failure|login failed|too many authentication failures)`,
				MinCount:    5,
				Enabled:     true,
			},
			{
				ID:          "SENT-002",
				Category:    "sqli_attempt",
				Severity:    "HIGH",
				Description: "SQL injection keyword pattern detected in log payload",
				Pattern:     `(?i)(union\s+select|'\s+or\s+'?1'?\s*=\s*'?1|information_schema|xp_cmdshell|sleep\(\d+\))`,
				MinCount:    1,
				Enabled:     true,
			},
			{
				ID:          "SENT-003",
				Category:    "path_traversal",
				Severity:    "HIGH",
				Description: "Path traversal or local file inclusion pattern detected",
				Pattern:     `(?i)(\.\./\.\./|%2e%2e%2f|%2e%2e/|/etc/passwd|/etc/shadow)`,
				MinCount:    1,
				Enabled:     true,
			},
			{
				ID:          "SENT-004",
				Category:    "remote_shell_exec",
				Severity:    "CRITICAL",
				Description: "Suspicious remote script pipe, reverse shell, or unauthorized sudo command",
				Pattern:     `(?i)((curl|wget)\s+.*\|\s*(sh|bash)|/dev/tcp/|nc\s+-[a-z]*e\s+|bash\s+-i|command\s+not\s+allowed)`,
				MinCount:    1,
				Enabled:     true,
			},
			{
				ID:          "SENT-005",
				Category:    "high_entropy_exfil",
				Severity:    "MEDIUM",
				Description: "High-entropy payload or DNS tunneling candidate detected",
				MinEntropy:  5.2,
				MinLength:   48,
				MinCount:    1,
				Enabled:     true,
			},
			{
				ID:          "SENT-007",
				Category:    "fatal_event",
				Severity:    "HIGH",
				Description: "Critical or fatal severity telemetry event",
				Levels:      []string{"FATAL"},
				MinCount:    1,
				Enabled:     true,
			},
			{
				ID:          "SENT-008",
				Category:    "error_burst",
				Severity:    "MEDIUM",
				Description: "Sustained ERROR volume spike for a single template",
				Levels:      []string{"ERROR"},
				MinCount:    25,
				Enabled:     true,
			},
		},
	}
}

// NewEngine compiles a RulePack into an immutable, concurrency-safe Engine.
func NewEngine(pack RulePack) (*Engine, error) {
	eng := &Engine{
		rules:        make([]compiledRule, 0, len(pack.Rules)),
		suppressions: make([]compiledSuppression, 0, len(pack.Suppressions)),
	}

	seenIDs := make(map[string]struct{}, len(pack.Rules))
	for _, r := range pack.Rules {
		if !r.Enabled {
			continue
		}
		id := strings.TrimSpace(r.ID)
		if id == "" {
			return nil, fmt.Errorf("rule missing required id")
		}
		if strings.EqualFold(id, "SENT-006") {
			return nil, fmt.Errorf("rule id %q is reserved for built-in prompt-injection detection", id)
		}
		if _, dup := seenIDs[id]; dup {
			return nil, fmt.Errorf("duplicate enabled rule id %q", id)
		}
		sev := strings.ToUpper(strings.TrimSpace(r.Severity))
		switch sev {
		case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		default:
			return nil, fmt.Errorf("rule %q has invalid severity %q (accepted: LOW, MEDIUM, HIGH, CRITICAL)", id, r.Severity)
		}
		seenIDs[id] = struct{}{}
		r.ID = id
		r.Severity = sev
		cr := compiledRule{rule: r}
		if r.Pattern != "" {
			re, err := regexp.Compile(r.Pattern)
			if err != nil {
				return nil, fmt.Errorf("compile rule %s regex: %w", r.ID, err)
			}
			cr.re = re
		}
		if len(r.Services) > 0 {
			cr.services = make(map[string]struct{}, len(r.Services))
			for _, s := range r.Services {
				cr.services[strings.ToLower(strings.TrimSpace(s))] = struct{}{}
			}
		}
		if len(r.Levels) > 0 {
			cr.levels = make(map[string]struct{}, len(r.Levels))
			for _, l := range r.Levels {
				cr.levels[strings.ToUpper(strings.TrimSpace(l))] = struct{}{}
			}
		}
		eng.rules = append(eng.rules, cr)
	}

	for _, s := range pack.Suppressions {
		if strings.TrimSpace(s.Service) == "" && strings.TrimSpace(s.Template) == "" && strings.TrimSpace(s.Pattern) == "" {
			return nil, fmt.Errorf("suppression %q must specify at least one selector (service, template, or pattern)", s.ID)
		}
		cs := compiledSuppression{supp: s}
		if s.Pattern != "" {
			re, err := regexp.Compile(s.Pattern)
			if err != nil {
				return nil, fmt.Errorf("compile suppression %s regex: %w", s.ID, err)
			}
			cs.re = re
		}
		eng.suppressions = append(eng.suppressions, cs)
	}

	return eng, nil
}

// LoadEngine loads a JSON RulePack from path, or falls back to DefaultRulePack if path is empty.
func LoadEngine(path string) (*Engine, error) {
	if strings.TrimSpace(path) == "" {
		return NewEngine(DefaultRulePack())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rules file %q: %w", path, err)
	}
	var pack *RulePack
	if err := json.Unmarshal(data, &pack); err != nil {
		return nil, fmt.Errorf("parse rules file %q: %w", path, err)
	}
	if pack == nil {
		return nil, fmt.Errorf("parse rules file %q: rule pack must be a JSON object, not null", path)
	}
	return NewEngine(*pack)
}

// MatchEvent evaluates a single incoming LogEvent BEFORE window collapsing so:
//   - Message-pattern suppressions exclude only matching events (never sibling events in a window).
//   - MinLength and MinEntropy are enforced on the exact same event payload.
//   - Burst thresholds (e.g. SENT-001) count only events matching that rule's predicate.
//   - Service/level rules see each event's true identity even when window aggregation overflows.
//   - Deterministic signatures never depend on a bounded window sample cache.
func (e *Engine) MatchEvent(ev model.LogEvent, evEntropy float64, maxPromptBytes int) EventEvaluation {
	// 1. Check event-level suppressions (any suppression without a Template selector).
	for _, cs := range e.suppressions {
		if cs.supp.Template != "" {
			continue
		}
		if cs.supp.Service != "" && !strings.EqualFold(cs.supp.Service, ev.Service) {
			continue
		}
		if cs.re != nil && !cs.re.MatchString(ev.Message) {
			continue
		}
		return EventEvaluation{Suppressed: true}
	}

	var res EventEvaluation

	// 2. Check adversarial prompt-injection signals across message, service, and level.
	cleanMsg, msgSigs := security.SanitizeUntrustedLogText(ev.Message, maxPromptBytes)
	_, svcSigs := security.SanitizeUntrustedLogText(ev.Service, 128)
	_, lvlSigs := security.SanitizeUntrustedLogText(ev.Level, 64)
	injSignals := mergeUniqueSignals(msgSigs, svcSigs, lvlSigs)
	if len(injSignals) > 0 {
		res.InjectionSuspected = true
		res.InjectionSignals = injSignals
		res.InjectionSample = cleanMsg
		res.Matches = append(res.Matches, EventRuleMatch{
			RuleHit: model.RuleHit{
				RuleID:      "SENT-006",
				Category:    "prompt_injection_probe",
				Severity:    "HIGH",
				Description: "Adversarial LLM control delimiter or prompt-injection phrase detected in untrusted log",
			},
			MinCount:        1,
			SanitizedSample: cleanMsg,
			Entropy:         evEntropy,
		})
	}

	// 3. Evaluate every compiled rule against this exact event.
	svcLower := strings.ToLower(ev.Service)
	lvlUpper := strings.ToUpper(ev.Level)

	for _, cr := range e.rules {
		if len(cr.services) > 0 {
			if _, ok := cr.services[svcLower]; !ok {
				continue
			}
		}
		if len(cr.levels) > 0 {
			if _, ok := cr.levels[lvlUpper]; !ok {
				continue
			}
		}
		if cr.rule.MinLength > 0 && len(ev.Message) < cr.rule.MinLength {
			continue
		}
		if cr.rule.MinEntropy > 0 && evEntropy < cr.rule.MinEntropy {
			continue
		}
		if cr.re != nil && !cr.re.MatchString(ev.Message) {
			continue
		}
		minCount := cr.rule.MinCount
		if minCount == 0 {
			minCount = 1
		}
		res.Matches = append(res.Matches, EventRuleMatch{
			RuleHit: model.RuleHit{
				RuleID:      cr.rule.ID,
				Category:    cr.rule.Category,
				Severity:    cr.rule.Severity,
				Description: cr.rule.Description,
			},
			MinCount:        minCount,
			SanitizedSample: cleanMsg,
			Entropy:         evEntropy,
		})
	}

	return res
}

// SuppressedTemplatesForService returns the exact template strings suppressed by
// template-scoped (non-pattern) suppressions applicable to service. Returned strings
// reference the immutable compiled RulePack without copying untrusted event bytes.
func (e *Engine) SuppressedTemplatesForService(service string) []string {
	var out []string
	for _, cs := range e.suppressions {
		if cs.supp.Template == "" || cs.re != nil {
			continue
		}
		if cs.supp.Service != "" && !strings.EqualFold(cs.supp.Service, service) {
			continue
		}
		out = append(out, cs.supp.Template)
	}
	return out
}

// IsTemplateSuppressed evaluates template-scoped suppressions at window flush time.
func (e *Engine) IsTemplateSuppressed(service, tmpl string) bool {
	for _, cs := range e.suppressions {
		if cs.supp.Template == "" {
			continue
		}
		if cs.supp.Service != "" && !strings.EqualFold(cs.supp.Service, service) {
			continue
		}
		if cs.supp.Template != tmpl {
			continue
		}
		if cs.re != nil {
			continue // pattern-qualified template suppressions apply per sample, not blindly to the whole template
		}
		return true
	}
	return false
}

// Evaluate inspects a standalone TemplateWindow against suppressions, adversarial
// prompt-injection heuristics, and compiled deterministic rules.
// Enforces message-pattern suppressions per candidate sample, tests MinLength and
// MinEntropy on the same candidate sample, evaluates message-pattern rules strictly
// against unsuppressed sample messages (never falling back to w.Template), and counts
// only confirmed matching samples for message-predicate rules when exact match counts
// are unavailable. Callers with exact per-rule event match counts should use
// EvaluateWithMatchCounts.
func (e *Engine) Evaluate(w model.TemplateWindow, maxPromptBytes int) EvaluationResult {
	return e.EvaluateWithMatchCounts(w, nil, maxPromptBytes)
}

// EvaluateWithMatchCounts inspects a TemplateWindow using optional per-rule matching-event
// counts (keyed by rule ID). When matchCounts is non-nil, firing decisions use matchCounts[ruleID]
// directly (relying on MatchEvent for event-level service/pattern suppressions and applying
// only service-independent template suppressions at window level) and treat retained preview
// samples as optional evidence.
func (e *Engine) EvaluateWithMatchCounts(w model.TemplateWindow, matchCounts map[string]uint64, maxPromptBytes int) EvaluationResult {
	if matchCounts == nil {
		// Preview mode: service-only or template-only suppressions suppress the entire window.
		if e.isWindowSuppressed(w) {
			sanitized, _ := security.SanitizeUntrustedLogText(w.SampleLine, maxPromptBytes)
			return EvaluationResult{Suppressed: true, SanitizedSample: sanitized}
		}
	} else {
		// Exact mode: event-level service suppressions already ran in MatchEvent against
		// the untruncated service identity; only apply service-independent template suppressions
		// here so clipped 128-byte display names never falsely discard exact matches.
		if e.isGlobalTemplateSuppressed(w.Template) {
			sanitized, _ := security.SanitizeUntrustedLogText(w.SampleLine, maxPromptBytes)
			return EvaluationResult{Suppressed: true, SanitizedSample: sanitized}
		}
	}

	type previewSample struct {
		text      string
		truncated bool
	}

	// Build candidate list excluding complete samples matched by a message-pattern suppression.
	// Never apply a message-pattern suppression regex to a clipped preview whose omitted tail
	// could falsify an anchored match (e.g. "^status ok$" on truncated "status ok").
	rawCandidates := make([]previewSample, 0, 1+len(w.AdditionalSamples))
	if w.SampleLine != "" {
		rawCandidates = append(rawCandidates, previewSample{text: w.SampleLine, truncated: w.SampleTruncated})
	}
	for i, s := range w.AdditionalSamples {
		trunc := i < len(w.AdditionalSamplesTruncated) && w.AdditionalSamplesTruncated[i]
		rawCandidates = append(rawCandidates, previewSample{text: s, truncated: trunc})
	}

	var activeSamples []previewSample
	for _, cand := range rawCandidates {
		if !cand.truncated && e.isSamplePatternSuppressed(w.Service, w.ServiceTruncated, w.Template, cand.text) {
			continue
		}
		activeSamples = append(activeSamples, cand)
	}
	// In preview-only mode (matchCounts == nil), suppress the window if every retained preview
	// matched a message-pattern suppression. When exact event-level matchCounts are provided,
	// unsuppressed events not in the preview cache must still be evaluated via matchCounts.
	if matchCounts == nil && len(rawCandidates) > 0 && len(activeSamples) == 0 {
		sanitized, _ := security.SanitizeUntrustedLogText(w.SampleLine, maxPromptBytes)
		return EvaluationResult{Suppressed: true, SanitizedSample: sanitized}
	}

	primarySample := w.SampleLine
	if len(activeSamples) > 0 {
		primarySample = activeSamples[0].text
	} else if len(rawCandidates) > 0 {
		primarySample = ""
	}
	sanitized, _ := security.SanitizeUntrustedLogText(primarySample, maxPromptBytes)

	var (
		injSignals []string
		injSample  string
	)
	sigSeen := make(map[string]struct{})
	for _, cand := range activeSamples {
		cleanCand, candSigs := security.SanitizeUntrustedLogText(cand.text, maxPromptBytes)
		if len(candSigs) > 0 && injSample == "" {
			injSample = cleanCand
		}
		for _, s := range candSigs {
			if _, ok := sigSeen[s]; !ok {
				sigSeen[s] = struct{}{}
				injSignals = append(injSignals, s)
			}
		}
	}

	res := EvaluationResult{
		SanitizedSample: sanitized,
	}
	if matchCounts != nil {
		// Exact mode: SENT-006 fires strictly from matchCounts["SENT-006"] > 0;
		// retain preview evidence only when exact count confirms an injection hit.
		if matchCounts["SENT-006"] > 0 {
			res.InjectionSuspected = true
			res.InjectionSignals = injSignals
			res.InjectionSample = injSample
			if injSample != "" {
				res.SanitizedSample = injSample
			}
			res.RuleHits = append(res.RuleHits, model.RuleHit{
				RuleID:      "SENT-006",
				Category:    "prompt_injection_probe",
				Severity:    "HIGH",
				Description: "Adversarial LLM control delimiter or prompt-injection phrase detected in untrusted log",
			})
		}
	} else if len(injSignals) > 0 {
		res.InjectionSuspected = true
		res.InjectionSignals = injSignals
		res.InjectionSample = injSample
		if injSample != "" {
			res.SanitizedSample = injSample
		}
		res.RuleHits = append(res.RuleHits, model.RuleHit{
			RuleID:      "SENT-006",
			Category:    "prompt_injection_probe",
			Severity:    "HIGH",
			Description: "Adversarial LLM control delimiter or prompt-injection phrase detected in untrusted log",
		})
	}

	svcLower := strings.ToLower(w.Service)
	lvlUpper := strings.ToUpper(w.Level)
	noSuppressedSamples := len(activeSamples) == len(rawCandidates)
	hasPatternSup := e.hasApplicablePatternSuppression(w.Service, w.ServiceTruncated, w.Template)

	for _, cr := range e.rules {
		// In preview-only mode, filter by window display Service/Level selectors.
		// When exact event-level matchCounts are provided, service/level predicates were
		// already evaluated per event (allowing global overflow windows with <MIXED> identity).
		if matchCounts == nil {
			if len(cr.services) > 0 {
				if _, ok := cr.services[svcLower]; !ok {
					continue
				}
			}
			if len(cr.levels) > 0 {
				if _, ok := cr.levels[lvlUpper]; !ok {
					continue
				}
			}
		}

		minReq := cr.rule.MinCount
		if minReq == 0 {
			minReq = 1
		}
		hasMsgPredicate := cr.re != nil || cr.rule.MinLength > 0 || cr.rule.MinEntropy > 0
		var (
			matchedSample string
			matchedCount  int
		)
		if !hasMsgPredicate {
			matchedSample = primarySample
			matchedCount = len(activeSamples)
		} else {
			for _, cand := range activeSamples {
				// Exclude clipped previews from confirmed regex or entropy matches:
				// a clipped prefix can satisfy anchored regexes ("^status ok$") or score
				// artificially higher entropy than the complete event payload.
				if cand.truncated && (cr.re != nil || cr.rule.MinEntropy > 0) {
					continue
				}
				if cr.rule.MinLength > 0 && len(cand.text) < cr.rule.MinLength {
					continue
				}
				if cr.rule.MinEntropy > 0 {
					ent := template.PeakShannonEntropy(cand.text)
					if cand.text == w.SampleLine && !cand.truncated && w.SampleEntropy > ent {
						ent = w.SampleEntropy
					}
					if ent < cr.rule.MinEntropy {
						continue
					}
				}
				if cr.re != nil && !cr.re.MatchString(cand.text) {
					continue
				}
				if matchedCount == 0 {
					matchedSample = cand.text
				}
				matchedCount++
			}
		}

		var effectiveCount uint64
		if matchCounts != nil {
			// Exact event-level match counts drive firing even when preview cache is empty;
			// retained sample matching is used only as optional evidence.
			effectiveCount = matchCounts[cr.rule.ID]
		} else if !hasMsgPredicate {
			// Use full window Count only when no applicable message-pattern suppression could
			// have excluded unobserved events in the window.
			if w.Template != "<OVERFLOW>" && noSuppressedSamples && !hasPatternSup {
				effectiveCount = w.Count
			} else {
				effectiveCount = uint64(len(activeSamples))
			}
		} else {
			// Without exact event match counts, never extrapolate w.Count across unsampled
			// events for message-predicate rules (count strictly confirmed matching previews).
			effectiveCount = uint64(matchedCount)
		}
		if effectiveCount < minReq {
			continue
		}

		// Preserve prompt-injection evidence when injection is suspected; otherwise surface matched sample.
		if !res.InjectionSuspected && matchedSample != "" && matchedSample != primarySample {
			res.SanitizedSample, _ = security.SanitizeUntrustedLogText(matchedSample, maxPromptBytes)
		}
		desc := cr.rule.Description
		if cr.rule.ID == "SENT-008" && (w.Template == "<OVERFLOW>" || strings.HasPrefix(w.TemplateID, "overflow:")) {
			desc = "Sustained overflow-wide ERROR volume spike across multiple templates"
		}
		res.RuleHits = append(res.RuleHits, model.RuleHit{
			RuleID:      cr.rule.ID,
			Category:    cr.rule.Category,
			Severity:    cr.rule.Severity,
			Description: desc,
		})
	}

	return res
}

func (e *Engine) isGlobalTemplateSuppressed(tmpl string) bool {
	if tmpl == "" {
		return false
	}
	for _, cs := range e.suppressions {
		if cs.re != nil || cs.supp.Service != "" {
			continue
		}
		if cs.supp.Template != "" && cs.supp.Template == tmpl {
			return true
		}
	}
	return false
}

func (e *Engine) hasApplicablePatternSuppression(service string, serviceTruncated bool, tmpl string) bool {
	for _, cs := range e.suppressions {
		if cs.re == nil {
			continue
		}
		// When service display identity is truncated, a service-scoped pattern suppression
		// might still match the true untruncated service, so conservatively treat it as applicable.
		if cs.supp.Service != "" && !serviceTruncated && !strings.EqualFold(cs.supp.Service, service) {
			continue
		}
		if cs.supp.Template != "" && cs.supp.Template != tmpl {
			continue
		}
		return true
	}
	return false
}

func (e *Engine) isWindowSuppressed(w model.TemplateWindow) bool {
	for _, cs := range e.suppressions {
		if cs.re != nil {
			continue // message-pattern suppressions are checked per sample, not blindly across the whole window
		}
		if cs.supp.Service != "" {
			if w.ServiceTruncated || !strings.EqualFold(cs.supp.Service, w.Service) {
				continue
			}
		}
		if cs.supp.Template != "" && cs.supp.Template != w.Template {
			continue
		}
		return true
	}
	return false
}

func (e *Engine) isSamplePatternSuppressed(service string, serviceTruncated bool, tmpl, sample string) bool {
	for _, cs := range e.suppressions {
		if cs.re == nil {
			continue
		}
		if cs.supp.Service != "" {
			if serviceTruncated || !strings.EqualFold(cs.supp.Service, service) {
				continue
			}
		}
		if cs.supp.Template != "" && cs.supp.Template != tmpl {
			continue
		}
		if cs.re.MatchString(sample) {
			return true
		}
	}
	return false
}

func mergeUniqueSignals(groups ...[]string) []string {
	var out []string
	var seen map[string]struct{}
	for _, g := range groups {
		for _, s := range g {
			if seen == nil {
				seen = make(map[string]struct{}, 4)
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
