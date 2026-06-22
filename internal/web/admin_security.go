package web

import (
	"net/http"
	"sort"
	"strings"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

type adminAuditPage struct {
	CSRFToken    string
	Me           *model.User
	Active       string
	Events       []auditView
	Total        int      // events scanned before filtering
	EventTypes   []string // distinct event names in the current window, for the filter
	Filtered     bool     // any filter active
	FilterResult string   // "", "ok", or "fail"
	FilterEvent  string   // selected event type, or ""
	FilterQuery  string   // free-text user/IP search
}

type auditView struct {
	Time     string
	Event    string
	Username string
	ClientID string
	IP       string
	Success  bool
	Detail   string
}

func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	events, _ := s.db.ListAuditEvents(r.Context(), 200)

	result := r.URL.Query().Get("result") // "ok" | "fail" | ""
	eventType := r.URL.Query().Get("event")
	query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))

	// Distinct event names across the window populate the filter dropdown.
	seen := map[string]bool{}
	types := make([]string, 0, 16)
	for _, e := range events {
		if !seen[e.Event] {
			seen[e.Event] = true
			types = append(types, e.Event)
		}
	}
	sort.Strings(types)

	views := make([]auditView, 0, len(events))
	for _, e := range events {
		if result == "ok" && !e.Success {
			continue
		}
		if result == "fail" && e.Success {
			continue
		}
		if eventType != "" && e.Event != eventType {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(e.Username), query) && !strings.Contains(strings.ToLower(e.IP), query) {
			continue
		}
		views = append(views, auditView{
			Time:     e.CreatedAt.Format("2006-01-02 15:04:05 MST"),
			Event:    e.Event,
			Username: e.Username,
			ClientID: e.ClientID,
			IP:       e.IP,
			Success:  e.Success,
			Detail:   e.Detail,
		})
	}

	s.tmpl.render(w, http.StatusOK, "admin_audit", adminAuditPage{
		CSRFToken:    auth.CSRFToken(w, r, s.cookieSecure()),
		Me:           currentUser(r),
		Active:       "audit",
		Events:       views,
		Total:        len(events),
		EventTypes:   types,
		Filtered:     result != "" || eventType != "" || query != "",
		FilterResult: result,
		FilterEvent:  eventType,
		FilterQuery:  r.URL.Query().Get("q"),
	})
}

func (s *Server) handleAdminUnlockUser(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.db.ResetFailedLogins(r.Context(), id); err != nil {
		s.userActionError(w, r, http.StatusBadRequest, "Could not unlock user.")
		return
	}
	target, _ := s.db.GetUserByID(r.Context(), id)
	username := ""
	if target != nil {
		username = target.Username
	}
	s.audit(r, evtUserUnlocked, auditEntry{
		actorUserID: actorID(r), username: username, success: true, detail: "id=" + id,
	})
	s.userActionDone(w, r, id)
}

func (s *Server) handleAdminResetMFA(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.db.SetUserMFA(r.Context(), id, false, ""); err != nil {
		s.userActionError(w, r, http.StatusBadRequest, "Could not reset MFA.")
		return
	}
	_ = s.db.DeleteRecoveryCodes(r.Context(), id)
	target, _ := s.db.GetUserByID(r.Context(), id)
	username := ""
	if target != nil {
		username = target.Username
	}
	s.audit(r, evtMFAReset, auditEntry{
		actorUserID: actorID(r), username: username, success: true, detail: "id=" + id,
	})
	s.userActionDone(w, r, id)
}

// actorID returns the acting admin's user id from the request context.
func actorID(r *http.Request) string {
	if u := currentUser(r); u != nil {
		return u.ID
	}
	return ""
}
