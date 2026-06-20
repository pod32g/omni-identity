package web

import (
	"net/http"
	"time"

	"github.com/pod32g/omni-identity/internal/auth"
	"github.com/pod32g/omni-identity/internal/model"
)

const recoveryCodeCount = 10

type mfaSetupPage struct {
	CSRFToken string
	Me        *model.User
	Active    string
	Secret    string
	OTPAuth   string
	Error     string
}

type mfaEnabledPage struct {
	CSRFToken     string
	Me            *model.User
	Active        string
	RecoveryCodes []string
}

// mfaIssuer is the label shown in authenticator apps.
func (s *Server) mfaIssuer() string {
	if b := s.branding.Current(); b.ProductName != "" {
		return b.ProductName
	}
	return "Omni Identity"
}

// handleMFASetup generates a fresh secret, stores it (disabled) and shows the
// enrollment QR/secret + a confirmation form.
func (s *Server) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	user := currentUser(r)
	if user.MFAEnabled {
		http.Redirect(w, r, "/account", http.StatusSeeOther)
		return
	}
	secret, err := auth.GenerateTOTPSecret()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	enc, err := s.enc.Encrypt(secret)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Persist the candidate secret with MFA still disabled; it only takes effect
	// once the user confirms a valid code.
	if err := s.db.SetUserMFA(r.Context(), user.ID, false, enc); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.tmpl.render(w, http.StatusOK, "mfa_setup", mfaSetupPage{
		CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
		Me:        user,
		Active:    "account",
		Secret:    secret,
		OTPAuth:   auth.TOTPProvisioningURI(secret, s.mfaIssuer(), user.Email),
	})
}

// handleMFAEnable confirms enrollment: verify a code against the stored secret,
// then enable MFA and issue recovery codes.
func (s *Server) handleMFAEnable(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	user := currentUser(r)
	secret, err := s.enc.Decrypt(user.TOTPSecret)
	if err != nil || secret == "" {
		http.Redirect(w, r, "/account/mfa/setup", http.StatusSeeOther)
		return
	}
	code := r.PostFormValue("code")
	if !auth.VerifyTOTP(secret, code, time.Now().UTC()) {
		s.tmpl.render(w, http.StatusUnauthorized, "mfa_setup", mfaSetupPage{
			CSRFToken: auth.CSRFToken(w, r, s.cookieSecure()),
			Me:        user, Active: "account",
			Secret:  secret,
			OTPAuth: auth.TOTPProvisioningURI(secret, s.mfaIssuer(), user.Email),
			Error:   "That code didn't match. Try again.",
		})
		return
	}
	if err := s.db.SetUserMFA(r.Context(), user.ID, true, user.TOTPSecret); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	plain, records := newRecoveryCodeSet(recoveryCodeCount)
	if err := s.db.ReplaceRecoveryCodes(r.Context(), user.ID, records); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.audit(r, evtMFAEnrolled, auditEntry{actorUserID: user.ID, username: user.Username, success: true})
	s.tmpl.render(w, http.StatusOK, "mfa_enabled", mfaEnabledPage{
		CSRFToken:     auth.CSRFToken(w, r, s.cookieSecure()),
		Me:            user,
		Active:        "account",
		RecoveryCodes: plain,
	})
}

// handleMFADisable turns MFA off after re-authenticating with the password.
func (s *Server) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	if !s.csrfOK(w, r) {
		return
	}
	user := currentUser(r)
	if ok, _ := auth.VerifyPassword(r.PostFormValue("password"), user.PasswordHash); !ok {
		s.renderAccount(w, r, http.StatusUnauthorized, "Your password is incorrect.", "")
		return
	}
	if err := s.db.SetUserMFA(r.Context(), user.ID, false, ""); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = s.db.DeleteRecoveryCodes(r.Context(), user.ID)
	s.audit(r, evtMFADisabled, auditEntry{actorUserID: user.ID, username: user.Username, success: true})
	s.renderAccount(w, r, http.StatusOK, "", "Two-factor authentication disabled.")
}
