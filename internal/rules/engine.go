package rules

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"github.com/vpsik-lab/vpsGuard/internal/config"
	"github.com/vpsik-lab/vpsGuard/internal/pipeline"
)

type Rule struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Conditions  map[string]string `yaml:"conditions"`
	Action      string            `yaml:"action"`
	ScoreAdd    int               `yaml:"score_weight"`
	Duration    string            `yaml:"duration"`
}

type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

type Engine struct {
	cfg    *config.Config
	logger *zap.Logger
	mu     sync.RWMutex
	rules  []Rule
}

func NewEngine(cfg *config.Config, logger *zap.Logger) *Engine {
	return &Engine{
		cfg:    cfg,
		logger: logger,
	}
}

func (e *Engine) LoadDefaults() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules = []Rule{
		{
			Name:        "aggressive_ssh",
			Description: "Block IPs with high SSH failure rate",
			Conditions: map[string]string{
				"type":           string(pipeline.EventSSHFailedLogin),
				"attempts":       ">10",
				"window_seconds": "<60",
			},
			Action:   "block",
			ScoreAdd: 40,
			Duration: "24h",
		},
		{
			Name:        "port_scan_detected",
			Description: "Block known port scanners",
			Conditions: map[string]string{
				"type": string(pipeline.EventPortScan),
			},
			Action:   "block",
			ScoreAdd: 35,
			Duration: "1h",
		},
		{
			Name:        "invalid_user_attempt",
			Description: "Block IPs trying non-existent users",
			Conditions: map[string]string{
				"type":     string(pipeline.EventInvalidUser),
				"attempts": ">3",
			},
			Action:   "block",
			ScoreAdd: 20,
			Duration: "15m",
		},

	}
}

func (e *Engine) LoadFromYAML(data []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return err
	}
	e.rules = rs.Rules
	return nil
}

func (e *Engine) Evaluate(evt pipeline.Envelope) []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var matched []Rule
	for _, rule := range e.rules {
		if matchRule(rule, evt) {
			matched = append(matched, rule)
		}
	}
	return matched
}

func matchRule(rule Rule, evt pipeline.Envelope) bool {
	for key, val := range rule.Conditions {
		switch key {
		case "type":
			if string(evt.Event.EventType()) != val {
				return false
			}
		case "source":
			if evt.Source != val {
				return false
			}
		case "attempts", "window_seconds", "confidence":
			fieldVal, ok := getFieldValue(evt, key)
			if !ok {
				return false
			}
			if !compareNumeric(fieldVal, val) {
				return false
			}
		}
	}
	return true
}

func getFieldValue(evt pipeline.Envelope, field string) (int, bool) {
	switch field {
	case "attempts":
		switch e := evt.Event.(type) {
		case pipeline.SSHFailedLogin:
			return e.Attempts, true
		}
	case "window_seconds":
		switch e := evt.Event.(type) {
		case pipeline.SSHFailedLogin:
			return e.WindowSec, true
		}
	case "confidence":
		return 0, false
	}
	return 0, false
}

func compareNumeric(fieldVal int, condition string) bool {
	condition = strings.TrimSpace(condition)
	if len(condition) < 2 {
		return false
	}

	var op string
	var valStr string

	if condition[0] == '>' || condition[0] == '<' {
		if len(condition) > 1 && (condition[1] == '=') {
			op = condition[:2]
			valStr = condition[2:]
		} else {
			op = condition[:1]
			valStr = condition[1:]
		}
	} else if condition[0] == '=' {
		if len(condition) > 1 && condition[1] == '=' {
			op = "=="
			valStr = condition[2:]
		} else {
			op = "="
			valStr = condition[1:]
		}
	} else {
		return false
	}

	valStr = strings.TrimSpace(valStr)
	threshold, err := strconv.Atoi(valStr)
	if err != nil {
		return false
	}

	switch op {
	case ">":
		return fieldVal > threshold
	case "<":
		return fieldVal < threshold
	case ">=":
		return fieldVal >= threshold
	case "<=":
		return fieldVal <= threshold
	case "==", "=":
		return fieldVal == threshold
	default:
		return false
	}
}

func (e *Engine) String() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return fmt.Sprintf("Engine{rules=%d}", len(e.rules))
}
