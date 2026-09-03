package enrollment

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PAM socket protocol (docs/LINUX-LOGIN-ARCHITECTURE.md §6): newline-delimited
// lines between pam_omni.so and the daemon. Only root may connect.

// PAMSocketName is the socket file under the runtime dir.
const PAMSocketName = "pam.sock"

// sockConversation adapts one socket connection to Conversation.
type sockConversation struct {
	w *bufio.Writer
	r *bufio.Reader
}

func sanitizeLine(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", "\n")
}

func (c *sockConversation) send(prefix, text string) error {
	// Multi-line info is allowed: the module receives each line separately.
	for i, line := range strings.Split(sanitizeLine(text), "\n") {
		p := prefix
		if i > 0 && (prefix == "P" || prefix == "E") {
			p = "I"
		}
		if _, err := c.w.WriteString(p + " " + line + "\n"); err != nil {
			return err
		}
	}
	return c.w.Flush()
}

func (c *sockConversation) Info(text string)  { _ = c.send("I", text) }
func (c *sockConversation) Error(text string) { _ = c.send("W", text) }

func (c *sockConversation) Prompt(text string, echo bool) (string, error) {
	prefix := "P"
	if echo {
		prefix = "E"
	}
	// Send the prompt's text: the last line of a multi-line prompt is the
	// actual prompt, earlier lines are info.
	lines := strings.Split(sanitizeLine(text), "\n")
	for _, l := range lines[:len(lines)-1] {
		if err := c.send("I", l); err != nil {
			return "", err
		}
	}
	if _, err := c.w.WriteString(prefix + " " + lines[len(lines)-1] + "\n"); err != nil {
		return "", err
	}
	if err := c.w.Flush(); err != nil {
		return "", err
	}
	line, err := c.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, "A ") && line != "A" {
		return "", fmt.Errorf("protocol: expected answer, got %q", line)
	}
	return strings.TrimPrefix(strings.TrimPrefix(line, "A"), " "), nil
}

func (c *sockConversation) result(v Verdict, user, reason string) {
	switch v {
	case VerdictOK:
		_ = c.send("R", "OK "+user)
	case VerdictIgnore:
		_ = c.send("R", "IGNORE")
	default:
		_ = c.send("R", "FAIL "+reason)
	}
}

// ServePAM listens on the root-only Unix socket and answers PAM requests
// until ctx is cancelled.
func (a *Agent) ServePAM(ctx context.Context, accounts LocalAccounts, pol LoginPolicy, logf func(string, ...any)) error {
	if err := os.MkdirAll(a.RuntimeDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(a.RuntimeDir, PAMSocketName)
	_ = os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	logf("pam socket listening at %s", path)
	for {
		conn, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			logf("pam socket accept: %v", err)
			continue
		}
		go a.handlePAMConn(ctx, conn, accounts, pol, logf)
	}
}

func (a *Agent) handlePAMConn(ctx context.Context, conn net.Conn, accounts LocalAccounts, pol LoginPolicy, logf func(string, ...any)) {
	defer conn.Close()
	if uc, ok := conn.(*net.UnixConn); ok {
		if err := requireRootPeer(uc); err != nil {
			logf("pam socket: rejected peer: %v", err)
			return
		}
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Minute))
	c := &sockConversation{w: bufio.NewWriter(conn), r: bufio.NewReader(conn)}
	first, err := c.r.ReadString('\n')
	if err != nil {
		if !errors.Is(err, io.EOF) {
			logf("pam socket: read: %v", err)
		}
		return
	}
	fields := strings.Fields(first)
	if len(fields) < 2 {
		c.result(VerdictFail, "", "bad request")
		return
	}
	user := fields[1]
	switch fields[0] {
	case "AUTH":
		lc := LoginContext{Username: user}
		if len(fields) > 2 {
			lc.Service = fields[2]
		}
		if len(fields) > 3 && fields[3] != "-" {
			lc.RHost = fields[3]
		}
		cctx, cancel := context.WithTimeout(ctx, 12*time.Minute)
		defer cancel()
		v := a.Login(cctx, c, lc, accounts, pol)
		logf("pam auth user=%s service=%s verdict=%d", user, lc.Service, v)
		c.result(v, user, "authentication failed")
	case "ACCT":
		v := a.Account(user, accounts, pol)
		c.result(v, user, "account revoked")
	default:
		c.result(VerdictFail, "", "unknown request")
	}
}
