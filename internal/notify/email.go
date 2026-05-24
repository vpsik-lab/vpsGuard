package notify

import (
	"context"
	"fmt"
	"net/smtp"

	"go.uber.org/zap"
)

type EmailNotifier struct {
	host   string
	port   int
	user   string
	pass   string
	from   string
	to     string
	logger *zap.Logger
}

func NewEmailNotifier(host string, port int, user, pass, from, to string, logger *zap.Logger) *EmailNotifier {
	return &EmailNotifier{
		host:   host,
		port:   port,
		user:   user,
		pass:   pass,
		from:   from,
		to:     to,
		logger: logger,
	}
}

func (n *EmailNotifier) Send(ctx context.Context, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", n.host, n.port)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s", n.from, n.to, subject, body)

	auth := smtp.PlainAuth("", n.user, n.pass, n.host)

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	return smtp.SendMail(addr, auth, n.from, []string{n.to}, []byte(msg))
}
