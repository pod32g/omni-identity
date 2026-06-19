package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFTokenSetsCookieWhenAbsent(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)

	tok := CSRFToken(rr, req, false)
	if tok == "" {
		t.Fatal("expected a non-empty token")
	}
	var found string
	for _, c := range rr.Result().Cookies() {
		if c.Name == csrfCookieName {
			found = c.Value
		}
	}
	if found != tok {
		t.Errorf("cookie value %q != returned token %q", found, tok)
	}
}

func TestCSRFTokenReusesExistingCookie(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "existing-token"})

	if tok := CSRFToken(rr, req, false); tok != "existing-token" {
		t.Errorf("token = %q, want existing-token", tok)
	}
}

func TestValidateCSRFToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "secret123"})

	if !ValidateCSRFToken(req, "secret123") {
		t.Error("matching token should validate")
	}
	if ValidateCSRFToken(req, "wrong") {
		t.Error("mismatched token must not validate")
	}
	if ValidateCSRFToken(req, "") {
		t.Error("empty submitted token must not validate")
	}
}

func TestValidateCSRFTokenNoCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	if ValidateCSRFToken(req, "anything") {
		t.Error("must not validate without a csrf cookie")
	}
}
