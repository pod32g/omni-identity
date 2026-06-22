package logship

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type capture struct {
	mu      sync.Mutex
	records []map[string]any
	keys    []string
}

func (c *capture) handler(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = append(c.keys, r.Header.Get("X-Api-Key"))
	sc := bufio.NewScanner(r.Body)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err == nil {
			c.records = append(c.records, m)
		}
	}
	w.WriteHeader(http.StatusOK)
}

func (c *capture) snapshot() ([]map[string]any, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string]any(nil), c.records...), append([]string(nil), c.keys...)
}

func TestHandlerShipsNDJSONWithKey(t *testing.T) {
	cap := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(cap.handler))
	defer srv.Close()

	h, err := NewHandler(Config{URL: srv.URL, APIKey: "k-secret", Service: "omni-identity", FlushInterval: 30 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(h)
	log.Info("http_request", "method", "GET", "path", "/login", "status", 200)
	log.Warn("slow", "duration_ms", 1200)

	if err := h.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}

	recs, keys := cap.snapshot()
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d: %+v", len(recs), recs)
	}
	for _, k := range keys {
		if k != "k-secret" {
			t.Fatalf("missing/incorrect api key: %q", k)
		}
	}
	r0 := recs[0]
	if r0["service"] != "omni-identity" || r0["message"] != "http_request" || r0["level"] != "info" {
		t.Fatalf("bad record: %+v", r0)
	}
	if r0["method"] != "GET" || r0["path"] != "/login" {
		t.Fatalf("attrs not flattened: %+v", r0)
	}
}

func TestHandlerRespectsLevel(t *testing.T) {
	cap := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(cap.handler))
	defer srv.Close()

	h, err := NewHandler(Config{URL: srv.URL, APIKey: "k", Service: "omni-identity", Level: slog.LevelWarn, FlushInterval: 30 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(h)
	log.Info("http_request", "status", 200) // below threshold → must not ship
	log.Warn("login.failed", "username", "x")
	if err := h.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}

	recs, _ := cap.snapshot()
	if len(recs) != 1 || recs[0]["message"] != "login.failed" {
		t.Fatalf("level threshold not honored, got: %+v", recs)
	}
}

func TestHandlerNeverBlocksOnOverflow(t *testing.T) {
	// Point at a black-hole server (hangs) and use a tiny buffer; Handle must
	// stay non-blocking and just drop.
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	defer srv.Close()
	defer close(block)

	h, err := NewHandler(Config{URL: srv.URL, APIKey: "k", BufferSize: 4, BatchSize: 1, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(h)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5000; i++ {
			log.Info("flood", "i", i)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("logging blocked under overflow")
	}
	if h.Dropped() == 0 {
		t.Fatal("expected some dropped records under overflow")
	}
}

func TestFanoutTees(t *testing.T) {
	var a, b bytes.Buffer
	h := Fanout(
		slog.NewJSONHandler(&a, &slog.HandlerOptions{Level: slog.LevelInfo}),
		slog.NewTextHandler(&b, &slog.HandlerOptions{Level: slog.LevelInfo}),
	)
	slog.New(h).Info("hello", "k", "v")
	if !bytes.Contains(a.Bytes(), []byte("hello")) || !bytes.Contains(a.Bytes(), []byte(`"k":"v"`)) {
		t.Fatalf("json child missing record: %s", a.String())
	}
	if !bytes.Contains(b.Bytes(), []byte("hello")) || !bytes.Contains(b.Bytes(), []byte("k=v")) {
		t.Fatalf("text child missing record: %s", b.String())
	}
}
