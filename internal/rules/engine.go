package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
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

// Suppression silences known benign services or message patterns before rule evaluation.
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

// Engine evaluates collapsed Tier 0 TemplateWindows against precompiled RE2 rules
// and prompt-injection heuristics. For a fixed rule pack of size |R|, each regex
// scan runs in linear O(L) time in input length L (total O(|R| * L) across active rules).
type Engine struct {
	rules        []compiledRule
	suppressions []compiledSuppression
}

// EvaluationResult bundles deterministic rule hits and adversarial injection signals
// for a single TemplateWindow.
type EvaluationResult struct {
	Suppressed         bool
	RuleHits           []model.RuleHit
	InjectionSuspected bool
	InjectionSignals   []string
	SanitizedSample    string
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

	for _, r := range pack.Rules {
		if !r.Enabled {
			continue
		}
		if strings.TrimSpace(r.ID) == "" {
			return nil, fmt.Errorf("rule missing required id")
		}
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
	var pack RulePack
	if err := json.Unmarshal(data, &pack); err != nil {
		return nil, fmt.Errorf("parse rules file %q: %w", path, err)
	}
	return NewEngine(pack)
}

// Evaluate inspects a TemplateWindow (including SampleLine, Template, and any retained
// AdditionalSamples) against suppressions, adversarial prompt-injection heuristics,
// and compiled deterministic rules.
func (e *Engine) Evaluate(w model.TemplateWindow, maxPromptBytes int) EvaluationResult {
	sanitized, injSignals := security.SanitizeUntrustedLogText(w.SampleLine, maxPromptBytes)

	// Also inspect retained AdditionalSamples for prompt-injection cues so an adversarial
	// payload cannot hide behind a higher-entropy benign sample in the same cluster.
	sigSet := make(map[string]struct{}, len(injSignals))
	for _, s := range injSignals {
		sigSet[s] = struct{}{}
	}
	for _, extra := range w.AdditionalSamples {
		extraClean, extraSigs := security.SanitizeUntrustedLogText(extra, maxPromptBytes)
		if len(extraSigs) > 0 && len(injSignals) == 0 {
			sanitized = extraClean
		}
		for _, s := range extraSigs {
			if _, exists := sigSet[s]; !exists {
				sigSet[s] = struct{}{}
				injSignals = append(injSignals, s)
			}
		}
	}

	res := EvaluationResult{
		InjectionSuspected: len(injSignals) > 0,
		InjectionSignals:   injSignals,
		SanitizedSample:    sanitized,
	}

	if e.isSuppressed(w) {
		res.Suppressed = true
		return res
	}

	if res.InjectionSuspected {
		res.RuleHits = append(res.RuleHits, model.RuleHit{
			RuleID:      "SENT-006",
			Category:    "prompt_injection_probe",
			Severity:    "HIGH",
			Description: "Adversarial LLM control delimiter or prompt-injection phrase detected in untrusted log",
		})
	}

	svcLower := strings.ToLower(w.Service)
	lvlUpper := strings.ToUpper(w.Level)

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
		if cr.rule.MinCount > 0 && w.Count < cr.rule.MinCount {
			continue
		}
		if cr.rule.MinEntropy > 0 && w.SampleEntropy < cr.rule.MinEntropy {
			continue
		}
		if cr.re != nil {
			matchedSample, ok := matchRuleRegex(cr.re, w, cr.rule.MinLength)
			if !ok {
				continue
			}
			// If a secondary evidence sample matched a signature (e.g. /etc/passwd in wildcard slot),
			// surface that sanitized evidence sample in the alert.
			if matchedSample != "" && matchedSample != w.SampleLine {
				res.SanitizedSample, _ = security.SanitizeUntrustedLogText(matchedSample, maxPromptBytes)
			}
		} else if cr.rule.MinLength > 0 && maxWindowSampleLength(w) < cr.rule.MinLength {
			continue
		}
		res.RuleHits = append(res.RuleHits, model.RuleHit{
			RuleID:      cr.rule.ID,
			Category:    cr.rule.Category,
			Severity:    cr.rule.Severity,
			Description: cr.rule.Description,
		})
	}

	return res
}

func matchRuleRegex(re *regexp.Regexp, w model.TemplateWindow, minLen int) (string, bool) {
	if (minLen <= 0 || len(w.SampleLine) >= minLen) && re.MatchString(w.SampleLine) {
		return w.SampleLine, true
	}
	if (minLen <= 0 || len(w.Template) >= minLen) && re.MatchString(w.Template) {
		return w.SampleLine, true
	}
	for _, extra := range w.AdditionalSamples {
		if (minLen <= 0 || len(extra) >= minLen) && re.MatchString(extra) {
			return extra, true
		}
	}
	return "", false
}

func maxWindowSampleLength(w model.TemplateWindow) int {
	best := len(w.SampleLine)
	for _, extra := range w.AdditionalSamples {
		if len(extra) > best {
			best = len(extra)
		}
	}
	return best
}

func (e *Engine) isSuppressed(w model.TemplateWindow) bool {
	for _, cs := range e.suppressions {
		if cs.supp.Service != "" && !strings.EqualFold(cs.supp.Service, w.Service) {
			continue
		}
		if cs.supp.Template != "" && cs.supp.Template != w.Template {
			continue
		}
		if cs.re != nil && !cs.re.MatchString(w.SampleLine) {
			continue
		}
		return true
	}
	return false
}
