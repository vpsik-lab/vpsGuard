package monitor

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/vps-guard/vps-guard/internal/pipeline"
)

type ParsedEvent struct {
	Type     string
	IP       string
	Username string
	Port     string
}

type LogParser struct {
	sshFailed   *regexp.Regexp
	invalidUser *regexp.Regexp
}

func NewLogParser() *LogParser {
	return &LogParser{
		sshFailed:   regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)`),
		invalidUser: regexp.MustCompile(`Invalid user (\S+) from (\S+)`),
	}
}

func (p *LogParser) Parse(line string) *ParsedEvent {
	if matches := p.sshFailed.FindStringSubmatch(line); len(matches) >= 4 {
		username := matches[1]
		ip := matches[2]
		port := matches[3]
		if strings.Contains(line, "invalid user") {
			return &ParsedEvent{Type: "invalid_user", IP: ip, Username: username, Port: port}
		}
		return &ParsedEvent{Type: "ssh_failed", IP: ip, Username: username, Port: port}
	}
	if matches := p.invalidUser.FindStringSubmatch(line); len(matches) >= 3 {
		return &ParsedEvent{Type: "invalid_user", IP: matches[2], Username: matches[1]}
	}
	return nil
}

func (p *LogParser) ToEvent(pe *ParsedEvent) pipeline.Event {
	now := time.Now()
	base := pipeline.BaseEvent{
		Time:        now,
		IP:          pe.IP,
		SeverityVal: 5,
		PriorityVal: pipeline.PriorityMedium,
		Metadata: map[string]interface{}{
			"username": pe.Username,
			"port":     pe.Port,
		},
	}

	switch pe.Type {
	case "ssh_failed":
		base.Type = pipeline.EventSSHFailedLogin
		base.SeverityVal = 5
		base.PriorityVal = pipeline.PriorityHigh
		return pipeline.SSHFailedLogin{
			BaseEvent:  base,
			Username:   pe.Username,
			Attempts:   1,
			AuthMethod: "password",
		}
	case "invalid_user":
		base.Type = pipeline.EventInvalidUser
		base.SeverityVal = 6
		base.PriorityVal = pipeline.PriorityHigh
		return pipeline.InvalidUserEvent{
			BaseEvent: base,
			Username:  pe.Username,
		}
	default:
		base.Type = pipeline.EventSSHFailedLogin
		return pipeline.SSHFailedLogin{BaseEvent: base, Username: pe.Username}
	}
}

type FileTailer struct {
	file    *os.File
	path    string
	buf     []byte
}

func NewFileTailer(path string) (*FileTailer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	f.Seek(0, 2)
	return &FileTailer{file: f, path: path, buf: make([]byte, 4096)}, nil
}

func (t *FileTailer) ReadNewLines() []string {
	n, err := t.file.Read(t.buf)
	if err != nil || n == 0 {
		return nil
	}
	data := string(t.buf[:n])
	lines := strings.Split(data, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func (t *FileTailer) Close() error {
	return t.file.Close()
}

func generateID() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return fmt.Sprintf("evt_%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("evt_%x", n.Int64())
}
