package email

import (
	"strings"
	"testing"
)

func TestBuildMessageHasHeadersAndBody(t *testing.T) {
	msg := buildMessage("from@x.com", "to@y.com", "Hi", "body line")
	for _, want := range []string{"From: from@x.com", "To: to@y.com", "Subject: Hi", "body line"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
}

func TestSubjectHeaderInjectionStripped(t *testing.T) {
	msg := buildMessage("from@x.com", "to@y.com", "Hi\r\nBcc: evil@x.com", "b")
	if strings.Contains(msg, "Bcc:") && strings.Contains(msg, "\r\nBcc:") {
		t.Errorf("CRLF in subject was not neutralized:\n%q", msg)
	}
}

func TestRecipientWithCRLFRejected(t *testing.T) {
	s := &SMTPSender{Host: "localhost", Port: 25, From: "from@x.com"}
	if err := s.Send("to@y.com\r\nBcc: evil@x.com", "s", "b"); err == nil {
		t.Error("recipient with CRLF should be rejected before sending")
	}
}

func TestEnabled(t *testing.T) {
	if (&SMTPSender{}).Enabled() {
		t.Error("empty config should be disabled")
	}
	if !(&SMTPSender{Host: "h", From: "f"}).Enabled() {
		t.Error("host+from should be enabled")
	}
}
