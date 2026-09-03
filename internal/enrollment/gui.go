package enrollment

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
)

// Local enrollment GUI: `omni-enrollment gui` serves a small page on the
// loopback interface and opens it in the system browser (the pattern used by
// `tailscale web`). It drives the same ceremony as the CLI. Protection
// against other local users and against web pages in the same browser:
//   - binds to 127.0.0.1 only;
//   - the launch URL carries a one-time token; the first visit turns it into
//     a cookie and every request must present it (403 otherwise);
//   - state-changing requests must also send the token in a header
//     (double-submit CSRF), which a cross-site form cannot do;
//   - the Host header must be loopback (DNS-rebinding guard).

//go:embed gui.html
var guiFS embed.FS

// GUI is the local web front end.
type GUI struct {
	agent *Agent
	cfg   Config
	token string
	tmpl  *template.Template

	// IdleTimeout, when set, stops the server once no browser has talked to
	// it for that long and no enrollment is waiting for approval. The
	// desktop launcher uses it so a closed tab does not leave a root
	// process behind. Zero means serve until the context ends.
	IdleTimeout time.Duration

	mu       sync.Mutex
	enroll   *Enrollment
	phase    string // idle | waiting | done | error
	message  string
	waitCtx  context.CancelFunc
	lastSeen time.Time
	done     chan struct{}
	doneOnce sync.Once
}

// NewGUI prepares the front end for an agent with the default enrollment
// settings (issuer etc. can be edited on the page).
func NewGUI(a *Agent, cfg Config) (*GUI, error) {
	tmpl, err := template.ParseFS(guiFS, "gui.html")
	if err != nil {
		return nil, err
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return &GUI{agent: a, cfg: cfg, token: base64.RawURLEncoding.EncodeToString(b), tmpl: tmpl, phase: "idle", done: make(chan struct{})}, nil
}

// Done is closed when the server has stopped, whether because the context
// ended or because IdleTimeout elapsed.
func (g *GUI) Done() <-chan struct{} { return g.done }

func (g *GUI) touch() {
	g.mu.Lock()
	g.lastSeen = time.Now()
	g.mu.Unlock()
}

// idle reports whether nothing has used the page for IdleTimeout and no
// approval is pending.
func (g *GUI) idle() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.phase != "waiting" && time.Since(g.lastSeen) > g.IdleTimeout
}

// Serve listens on addr (loopback) and returns the URL to open. It serves
// until ctx is cancelled.
func (g *GUI) Serve(ctx context.Context, addr string) (string, error) {
	if addr == "" {
		addr = "127.0.0.1:0"
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || (host != "127.0.0.1" && host != "localhost" && host != "::1") {
		return "", errors.New("the GUI only listens on the loopback interface")
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return "", err
	}
	srv := &http.Server{Handler: g.handler(), ReadHeaderTimeout: 10 * time.Second}
	g.touch()
	stop := func() {
		g.mu.Lock()
		if g.waitCtx != nil {
			g.waitCtx()
		}
		g.mu.Unlock()
		_ = srv.Close()
		g.doneOnce.Do(func() { close(g.done) })
	}
	go func() {
		if g.IdleTimeout <= 0 {
			<-ctx.Done()
			stop()
			return
		}
		tick := time.NewTicker(min(g.IdleTimeout/4+time.Millisecond, 5*time.Second))
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				stop()
				return
			case <-tick.C:
				if g.idle() {
					stop()
					return
				}
			}
		}
	}()
	go func() { _ = srv.Serve(l) }()
	return fmt.Sprintf("http://%s/?t=%s", l.Addr().String(), g.token), nil
}

func (g *GUI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", g.handleIndex)
	mux.HandleFunc("GET /status", g.handleStatus)
	mux.HandleFunc("GET /qr.svg", g.handleQR)
	mux.HandleFunc("POST /enroll", g.handleEnroll)
	mux.HandleFunc("POST /cancel", g.handleCancel)
	mux.HandleFunc("POST /renew", g.handleRenew)
	mux.HandleFunc("POST /rotate", g.handleRotate)
	mux.HandleFunc("POST /unenroll", g.handleUnenroll)
	return g.guard(mux)
}

// guard enforces loopback Host, the session token, and CSRF on POSTs.
func (g *GUI) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Host
		if hh, _, err := net.SplitHostPort(h); err == nil {
			h = hh
		}
		if h != "127.0.0.1" && h != "localhost" && h != "::1" {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; script-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		// First visit: turn the URL token into a cookie and drop it from the URL.
		if t := r.URL.Query().Get("t"); t != "" && r.Method == http.MethodGet && r.URL.Path == "/" {
			if subtle.ConstantTimeCompare([]byte(t), []byte(g.token)) != 1 {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "omni_gui", Value: g.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		c, err := r.Cookie("omni_gui")
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(g.token)) != 1 {
			http.Error(w, "forbidden: open the URL printed by omni-enrollment gui", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Omni-GUI")), []byte(g.token)) != 1 {
			http.Error(w, "forbidden: missing CSRF header", http.StatusForbidden)
			return
		}
		g.touch()
		next.ServeHTTP(w, r)
	})
}

// view is the page/status model.
type view struct {
	Token       string
	Enrolled    bool
	State       *State
	Daemon      *Status
	Phase       string
	Message     string
	Link        string
	Code        string
	Expires     string
	Issuer      string
	Name        string
	KeyBackend  string
	KeyAlg      string
	Fingerprint string
	TPMDevice   string
	Insecure    bool
}

func (g *GUI) currentView() view {
	g.mu.Lock()
	defer g.mu.Unlock()
	v := view{Token: g.token, Phase: g.phase, Message: g.message, Issuer: g.cfg.Issuer, Name: g.cfg.Name,
		KeyBackend: orDefault(g.cfg.KeyBackend, KeyBackendFile), TPMDevice: g.cfg.TPMDevice, Insecure: g.cfg.AllowInsecureHTTP}
	if v.Name == "" {
		v.Name = LocalMetadata("").Name
	}
	if st, err := LoadState(g.agent.StateDir); err == nil {
		v.Enrolled, v.State = true, st
		v.Daemon, _ = ReadStatus(g.agent.RuntimeDir)
	}
	if g.enroll != nil {
		v.Link, v.Code = g.enroll.VerificationURIComplete(), g.enroll.UserCode()
		v.Expires = g.enroll.ExpiresAt().Format(time.Kitchen)
		v.KeyAlg, v.Fingerprint = g.enroll.KeyAlgorithm(), g.enroll.Fingerprint()
	}
	return v
}

func (g *GUI) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := g.tmpl.Execute(w, g.currentView()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (g *GUI) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	v := g.currentView()
	v.Token = ""
	_ = json.NewEncoder(w).Encode(v)
}

func (g *GUI) handleQR(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	e := g.enroll
	g.mu.Unlock()
	if e == nil {
		http.NotFound(w, r)
		return
	}
	svg, err := qrSVG(e.VerificationURIComplete())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	_, _ = w.Write([]byte(svg))
}

// handleEnroll starts the ceremony with the submitted settings and polls in
// the background; the page follows via /status.
func (g *GUI) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	g.mu.Lock()
	if g.enroll != nil && g.phase == "waiting" {
		g.mu.Unlock()
		http.Error(w, "an enrollment is already in progress", http.StatusConflict)
		return
	}
	cfg := g.cfg
	cfg.Issuer = strings.TrimSpace(r.PostFormValue("issuer"))
	cfg.Name = strings.TrimSpace(r.PostFormValue("name"))
	cfg.KeyBackend = r.PostFormValue("key_backend")
	cfg.TPMDevice = strings.TrimSpace(r.PostFormValue("tpm_device"))
	cfg.AllowInsecureHTTP = cfg.AllowInsecureHTTP || r.PostFormValue("allow_insecure_http") == "on"
	g.cfg = cfg
	g.mu.Unlock()
	if cfg.Issuer == "" {
		http.Error(w, "issuer is required", http.StatusBadRequest)
		return
	}
	e, err := g.agent.BeginEnrollment(r.Context(), cfg)
	if err != nil {
		g.setPhase("error", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Until(e.ExpiresAt())+10*time.Second)
	g.mu.Lock()
	g.enroll, g.phase, g.message, g.waitCtx = e, "waiting", "", cancel
	g.mu.Unlock()
	go func() {
		defer cancel()
		st, err := e.Wait(ctx, nil)
		if err != nil {
			g.setPhase("error", err.Error())
			g.mu.Lock()
			g.enroll = nil
			g.mu.Unlock()
			return
		}
		msg := "Enrolled as " + st.OwnerUsername + "."
		if st.Status == "pending" {
			msg += " The device is pending administrator approval."
		}
		g.setPhase("done", msg)
		g.mu.Lock()
		g.enroll = nil
		g.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"link": e.VerificationURIComplete(), "code": e.UserCode()})
}

func (g *GUI) setPhase(phase, msg string) {
	g.mu.Lock()
	g.phase, g.message = phase, msg
	g.mu.Unlock()
}

func (g *GUI) handleCancel(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	cancel, e := g.waitCtx, g.enroll
	g.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if e != nil {
		e.Abort()
	}
	g.setPhase("idle", "Enrollment cancelled.")
	g.mu.Lock()
	g.enroll = nil
	g.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (g *GUI) handleRenew(w http.ResponseWriter, r *http.Request) {
	st, tok, err := g.agent.Renew(r.Context())
	if err != nil {
		g.setPhase("error", "Renew failed: "+err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	g.setPhase("done", fmt.Sprintf("Device %s is %s; token valid for %d minutes.", st.Name, st.Status, tok.ExpiresIn/60))
	w.WriteHeader(http.StatusNoContent)
}

func (g *GUI) handleRotate(w http.ResponseWriter, r *http.Request) {
	st, err := g.agent.RotateKey(r.Context())
	if err != nil {
		g.setPhase("error", "Key rotation failed: "+err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	g.setPhase("done", "Key rotated; new fingerprint "+st.Fingerprint+".")
	w.WriteHeader(http.StatusNoContent)
}

func (g *GUI) handleUnenroll(w http.ResponseWriter, r *http.Request) {
	if err := g.agent.Unenroll(r.Context()); err != nil {
		g.setPhase("error", "Unenroll failed: "+err.Error())
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	g.setPhase("idle", "Device unenrolled; the key was removed.")
	w.WriteHeader(http.StatusNoContent)
}

// qrSVG renders a QR code as a crisp inline SVG.
func qrSVG(content string) (string, error) {
	q, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return "", err
	}
	bits := q.Bitmap()
	n := len(bits)
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" shape-rendering="crispEdges"><rect width="%d" height="%d" fill="#fff"/>`, n, n, n, n)
	for y, row := range bits {
		for x, dark := range row {
			if dark {
				fmt.Fprintf(&b, `<rect x="%d" y="%d" width="1" height="1" fill="#000"/>`, x, y)
			}
		}
	}
	b.WriteString("</svg>")
	return b.String(), nil
}
