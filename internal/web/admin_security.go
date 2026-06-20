package web

import (
	"net/http"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

type adminAuditPage struct {
	CSRFToken string
	Me        *model.User
	Active    string
	Events    []auditView
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
	views := make([]auditView, 0, len(events))
	for _, e := range events {
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
		CSRFToken: auth.CSRFToken(w, r, s.cfg.Cookies.Secure),
		Me:        currentUser(r),
		Active:    "audit",
		Events:    views,
	})
}

func (s *Server) handleAdminUnlockUser(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.db.ResetFailedLogins(r.Context(), id); err != nil {
		s.renderUsers(w, r, http.StatusBadRequest, "Could not unlock user.")
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
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (s *Server) handleAdminResetMFA(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	if err := s.db.SetUserMFA(r.Context(), id, false, ""); err != nil {
		s.renderUsers(w, r, http.StatusBadRequest, "Could not reset MFA.")
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
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// actorID returns the acting admin's user id from the request context.
func actorID(r *http.Request) string {
	if u := currentUser(r); u != nil {
		return u.ID
	}
	return ""
}
