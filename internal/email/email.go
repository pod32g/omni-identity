// Package email provides outbound transactional email (currently password
// reset) over SMTP, behind a small interface so handlers can be tested with a
// no-op or capturing sender.
package email

import (
	"fmt"
	"net/smtp"
	"strings"
)

// Sender delivers a message. Implementations must be safe for concurrent use.
type Sender interface {
	// Enabled reports whether email delivery is configured.
	Enabled() bool
	// Send delivers a plain-text message to a single recipient.
	Send(to, subject, body string) error
}

// SMTPSender sends mail via an SMTP server using STARTTLS + PLAIN auth.
type SMTPSender struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	StartTLS bool
}

// Enabled reports whether the minimum SMTP settings are present.
func (s *SMTPSender) Enabled() bool { return s != nil && s.Host != "" && s.From != "" }

// Send composes and delivers a single plain-text email.
func (s *SMTPSender) Send(to, subject, body string) error {
	if !s.Enabled() {
		return fmt.Errorf("email: SMTP is not configured")
	}
	if err := validateHeaderValue(to); err != nil {
		return fmt.Errorf("email: recipient: %w", err)
	}
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	msg := buildMessage(s.From, to, subject, body)

	var auth smtp.Auth
	if s.Username != "" {
		auth = smtp.PlainAuth("", s.Username, s.Password, s.Host)
	}
	// net/smtp.SendMail issues STARTTLS automatically when the server advertises
	// it; auth over a non-TLS connection is refused by the stdlib.
	return smtp.SendMail(addr, auth, s.From, []string{to}, []byte(msg))
}

// buildMessage assembles RFC 5322 headers + body. Subject is sanitized; the
// recipient is validated by the caller.
func buildMessage(from, to, subject, body string) string {
	subject = sanitizeHeader(subject)
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(strings.ReplaceAll(body, "\r\n", "\n"))
	return b.String()
}

// sanitizeHeader strips CR/LF to prevent header injection.
func sanitizeHeader(v string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(v)
}

// validateHeaderValue rejects addresses containing CR/LF (header injection).
func validateHeaderValue(v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("contains line breaks")
	}
	return nil
}
