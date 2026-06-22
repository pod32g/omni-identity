package web

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pod32g/omni-identity/internal/model"
)

// TestAdminHomeRendersDashboard verifies /admin now renders the overview
// dashboard (200) rather than redirecting to the users list.
func TestAdminHomeRendersDashboard(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	rr := adminGet(srv, "/admin", sid)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200 (dashboard, not a redirect)", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"Overview", "MFA adoption", "Recent activity"} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
}

// TestAdminUserDetailRenders verifies a known user renders the detail page with
// its management panels.
func TestAdminUserDetailRenders(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	u := createUser(t, srv, "detailme", "pw", false)
	rr := adminGet(srv, "/admin/users/"+u.ID, sid)
	if rr.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"detailme", "Set password", "Security"} {
		if !strings.Contains(body, want) {
			t.Errorf("user detail missing %q", want)
		}
	}
}

// TestAdminUserDetailNotFound verifies an unknown id 404s.
func TestAdminUserDetailNotFound(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	rr := adminGet(srv, "/admin/users/"+uuid.NewString(), sid)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rr.Code)
	}
}

// TestAdminAuditFilterNarrows verifies the result filter narrows the rendered
// event set server-side.
func TestAdminAuditFilterNarrows(t *testing.T) {
	srv := testServer(t)
	sid := adminSession(t, srv)
	now := time.Now().UTC()
	mustAudit(t, srv, &model.AuditEvent{ID: uuid.NewString(), CreatedAt: now, Event: "login.success", Username: "alice", IP: "10.0.0.1", Success: true})
	mustAudit(t, srv, &model.AuditEvent{ID: uuid.NewString(), CreatedAt: now, Event: "login.failed", Username: "mallory", IP: "10.0.0.2", Success: false})

	// Unfiltered: both events present.
	all := adminGet(srv, "/admin/audit", sid).Body.String()
	if !strings.Contains(all, "alice") || !strings.Contains(all, "mallory") {
		t.Fatal("unfiltered audit should list both events")
	}

	// Filter to failures only: mallory present, alice gone.
	fail := adminGet(srv, "/admin/audit?result=fail", sid).Body.String()
	if !strings.Contains(fail, "mallory") {
		t.Error("result=fail should keep the failed event")
	}
	// Note: "login.success" still appears in the event-type filter dropdown;
	// assert on the table row (>alice<) instead, which is dropped by the filter.
	if strings.Contains(fail, ">alice<") {
		t.Error("result=fail should drop the successful event row")
	}

	// Free-text search by user narrows too.
	q := adminGet(srv, "/admin/audit?q=alice", sid).Body.String()
	if !strings.Contains(q, "alice") || strings.Contains(q, "mallory") {
		t.Error("q=alice should keep only alice's event")
	}
}

func mustAudit(t *testing.T, srv *Server, e *model.AuditEvent) {
	t.Helper()
	if err := srv.db.AppendAuditEvent(context.Background(), e); err != nil {
		t.Fatalf("append audit: %v", err)
	}
}
