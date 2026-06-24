package web

import (
	"net/http"
	"strings"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/authn"
)

// directoryWriteCapable reports whether a write-capable directory client exists
// (LDAP enabled with a privileged bind). This is what makes the live management
// toggle meaningful; without it, the toggle is hidden and cannot be turned on.
func (s *Server) directoryWriteCapable() bool { return s.directory != nil }

// directoryManager returns the directory client when management is both possible
// (write-capable) and enabled live via the ldap_manage_enabled setting; nil
// otherwise. All create/edit/delete/set-password paths route through this, so the
// admin toggle takes effect immediately without a restart.
func (s *Server) directoryManager() authn.DirectoryManager {
	if s.directory == nil || !s.settings.Current().LDAPManageEnabled {
		return nil
	}
	return s.directory
}

// directoryEnabled reports whether directory management actions are currently
// available (configured and toggled on). The directory remains the source of
// truth; Omni only drives it.
func (s *Server) directoryEnabled() bool { return s.directoryManager() != nil }

// handleAdminCreateDirectoryUser provisions a new user in the canonical
// directory (LDAP Add), optionally sets an initial password, and then mirrors
// the entry locally. It is directory-first: nothing is written to Omni's mirror
// until the directory create succeeds. Called from handleAdminCreateUser when
// the create form selects the directory source.
func (s *Server) handleAdminCreateDirectoryUser(w http.ResponseWriter, r *http.Request, username, email, displayName, password string) {
	dir := s.directoryManager()
	if dir == nil {
		s.renderUsers(w, r, http.StatusBadRequest, "Directory management is not enabled.")
		return
	}
	if username == "" || email == "" {
		s.renderUsers(w, r, http.StatusBadRequest, "Username and email are required.")
		return
	}
	// Apply Omni's password policy as a floor when an initial password is given;
	// the directory enforces its own policy on top.
	if password != "" {
		if msg := auth.ValidatePassword(password, username, email, s.passwordPolicy()); msg != "" {
			s.renderUsers(w, r, http.StatusBadRequest, msg)
			return
		}
	}

	ctx := r.Context()
	dn, err := dir.CreateUser(ctx, authn.DirectoryUser{
		Username: username, Email: email, DisplayName: displayName,
	})
	if err != nil {
		s.renderUsers(w, r, http.StatusBadRequest, "Could not create the directory user (it may already exist, or the directory rejected the entry).")
		return
	}
	if password != "" {
		if err := dir.SetPassword(ctx, dn, password); err != nil {
			// The entry exists but has no usable password. Surface it so the admin
			// can set one from the user's page rather than silently shipping a
			// login-less account.
			s.renderUsers(w, r, http.StatusBadGateway, "Directory user created, but setting the initial password failed. Set it from the user's page.")
			return
		}
	}

	// Mirror the new entry locally so it appears in the admin panel immediately
	// (rather than only after first login). admin-ness comes from the directory's
	// group membership, never from this form.
	if _, err := s.db.UpsertExternalUser(ctx, dir.ID(), dn, username, email, displayName, false); err != nil {
		s.renderUsers(w, r, http.StatusConflict, "Directory user created, but it could not be mirrored locally (the username may collide with a local account).")
		return
	}
	s.audit(r, evtDirUserCreated, auditEntry{actorUserID: actorID(r), username: username, success: true, detail: "dn=" + dn})
	if password == "" {
		// An entry with no password can't bind — flag it so it isn't a silent
		// login-less account.
		s.renderUsersWithWarning(w, r, username+" was created in the directory without a password — they can't sign in until you set one from their page.")
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// handleAdminPromoteUser turns a local account into a directory-backed one in a
// single admin action. It links to an existing directory entry for the username
// when one is found, otherwise creates a new entry (optionally with an
// admin-supplied password). Directory-first: the entry must exist before the
// local row is re-pointed, so a failure leaves the local account untouched.
func (s *Server) handleAdminPromoteUser(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	dir := s.directoryManager()
	if dir == nil {
		s.userActionError(w, r, http.StatusBadRequest, "Directory management is not enabled.")
		return
	}
	user, err := s.db.GetUserByID(r.Context(), r.PathValue("id"))
	if err != nil || user == nil {
		s.userActionError(w, r, http.StatusNotFound, "User not found.")
		return
	}
	if !user.IsLocal() {
		s.userActionError(w, r, http.StatusBadRequest, "This account is already managed by the directory.")
		return
	}
	password := r.PostFormValue("password")

	ctx := r.Context()
	dn, found, err := dir.LookupDN(ctx, user.Username)
	if err != nil {
		s.userActionError(w, r, http.StatusBadGateway, "Could not query the directory.")
		return
	}

	linked := found
	if !found {
		// No existing entry — create one (validating the password as a floor when
		// supplied) and set the initial password if given.
		if password != "" {
			if msg := auth.ValidatePassword(password, user.Username, user.Email, s.passwordPolicy()); msg != "" {
				s.userActionError(w, r, http.StatusBadRequest, msg)
				return
			}
		}
		dn, err = dir.CreateUser(ctx, authn.DirectoryUser{Username: user.Username, Email: user.Email})
		if err != nil {
			s.userActionError(w, r, http.StatusBadGateway, "Could not create the directory entry.")
			return
		}
		if password != "" {
			if err := dir.SetPassword(ctx, dn, password); err != nil {
				s.userActionError(w, r, http.StatusBadGateway, "Directory entry created, but setting the password failed. Set it from the user's page.")
				return
			}
		}
	}

	// Re-point the local row at the directory entry; this clears the local hash.
	if err := s.db.LinkUserToExternal(ctx, user.ID, dir.ID(), dn); err != nil {
		s.userActionError(w, r, http.StatusConflict, "Could not link the account to the directory entry (it may already be linked to another user).")
		return
	}
	// Force the next sign-in through the directory bind.
	_, _ = s.db.DeleteSessionsForUser(ctx, user.ID, "")
	detail := "linked"
	if !linked {
		detail = "created"
	}
	s.audit(r, evtUserPromoted, auditEntry{actorUserID: actorID(r), username: user.Username, success: true, detail: detail + " dn=" + dn})
	// A freshly-created entry with no password can't bind — flag it (a linked
	// entry already has its own credential, so only warn on the create path).
	if !linked && password == "" {
		if u, err := s.db.GetUserByID(ctx, user.ID); err == nil && u != nil {
			s.renderUserDetailWithWarning(w, r, u, "Promoted "+user.Username+" and created a new directory entry with no password — set one below before they can sign in.")
			return
		}
	}
	s.userActionDone(w, r, user.ID)
}

// handleAdminUpdateDirectoryUser edits a directory user's mutable attributes
// (email, display name) in the directory, then refreshes the local mirror.
func (s *Server) handleAdminUpdateDirectoryUser(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	user, err := s.db.GetUserByID(r.Context(), id)
	if err != nil || user == nil {
		s.userActionError(w, r, http.StatusNotFound, "User not found.")
		return
	}
	dir := s.directoryManager()
	if user.IsLocal() || dir == nil {
		s.userActionError(w, r, http.StatusBadRequest, "This account is not a managed directory user.")
		return
	}
	email := strings.TrimSpace(r.PostFormValue("email"))
	displayName := strings.TrimSpace(r.PostFormValue("display_name"))
	if email == "" {
		s.userActionError(w, r, http.StatusBadRequest, "Email is required.")
		return
	}

	ctx := r.Context()
	if err := dir.UpdateUser(ctx, user.ExternalID, authn.DirectoryUser{
		Email: email, DisplayName: displayName,
	}); err != nil {
		s.userActionError(w, r, http.StatusBadGateway, "The directory rejected the update.")
		return
	}
	// Refresh the mirror's email; is_admin/disabled are preserved by reusing the
	// loaded row.
	user.Email = email
	if err := s.db.UpdateUser(ctx, user); err != nil {
		s.userActionError(w, r, http.StatusInternalServerError, "Directory updated, but the local mirror could not be refreshed.")
		return
	}
	s.audit(r, evtDirUserUpdated, auditEntry{actorUserID: actorID(r), username: user.Username, success: true, detail: "dn=" + user.ExternalID})
	s.userActionDone(w, r, id)
}

// handleAdminDeleteUser permanently removes a user. For a directory-backed user
// it deletes the directory entry first (directory-first), then the local mirror;
// for a local user it removes the local row. Guards prevent deleting your own
// account or the last remaining administrator.
func (s *Server) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	id := r.PathValue("id")
	if me := currentUser(r); me != nil && me.ID == id {
		s.userActionError(w, r, http.StatusBadRequest, "You cannot delete your own account.")
		return
	}
	user, err := s.db.GetUserByID(r.Context(), id)
	if err != nil || user == nil {
		s.userActionError(w, r, http.StatusNotFound, "User not found.")
		return
	}
	// Never delete the last enabled administrator.
	if user.IsAdmin && !user.Disabled {
		if n, err := s.db.CountAdmins(r.Context()); err == nil && n <= 1 {
			s.userActionError(w, r, http.StatusBadRequest, "You cannot delete the last administrator.")
			return
		}
	}

	ctx := r.Context()
	event := evtUserDeleted
	if !user.IsLocal() {
		dir := s.directoryManager()
		if dir == nil {
			s.userActionError(w, r, http.StatusBadRequest, "Directory management is not enabled; this user is managed by an external directory.")
			return
		}
		if err := dir.DeleteUser(ctx, user.ExternalID); err != nil {
			s.userActionError(w, r, http.StatusBadGateway, "The directory rejected the delete; nothing was removed.")
			return
		}
		event = evtDirUserDeleted
	}

	// Revoke sessions before removing the row so no live session outlives it.
	_, _ = s.db.DeleteSessionsForUser(ctx, id, "")
	if err := s.db.DeleteUser(ctx, id); err != nil {
		s.userActionError(w, r, http.StatusInternalServerError, "Could not delete the user.")
		return
	}
	s.audit(r, event, auditEntry{actorUserID: actorID(r), username: user.Username, success: true, detail: "id=" + id})
	// The detail page is gone now; always return to the list.
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}
