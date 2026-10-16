package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"pgpanel/internal/store"
)

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	_, oc, err := s.oauthConfig(r.Context())
	if err != nil {
		s.log.Error("oidc discovery", "err", err)
		s.fail(w, r, http.StatusServiceUnavailable, "The login provider is not reachable. Try again in a moment.")
		return
	}
	state, nonce, verifier := randomToken(), randomToken(), oauth2.GenerateVerifier()
	if err := s.store.SaveOIDCLogin(r.Context(), state, verifier, nonce); err != nil {
		s.internalError(w, r, err)
		return
	}
	// binds the state to this browser, the login cannot be completed in another one
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: state, Path: "/", MaxAge: 600, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, oc.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), http.StatusFound)
}

type claims struct {
	Subject           string   `json:"sub"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Groups            []string `json:"groups"`
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	http.SetCookie(w, &http.Cookie{Name: stateCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})

	state := r.URL.Query().Get("state")
	c, err := r.Cookie(stateCookie)
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
		s.fail(w, r, http.StatusBadRequest, "Login expired or was started in another browser. Please sign in again.")
		return
	}
	verifier, nonce, err := s.store.TakeOIDCLogin(ctx, state)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, http.StatusBadRequest, "Login expired. Please sign in again.")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		s.fail(w, r, http.StatusForbidden, "Login was refused by the provider.")
		return
	}

	provider, oc, err := s.oauthConfig(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	token, err := oc.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(verifier))
	if err != nil {
		s.log.Warn("oidc code exchange failed", "err", err)
		s.fail(w, r, http.StatusForbidden, "Login failed.")
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		s.fail(w, r, http.StatusForbidden, "Login failed: no ID token.")
		return
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: s.cfg.ClientID}).Verify(ctx, rawID)
	if err != nil || subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(nonce)) != 1 {
		s.log.Warn("oidc id token rejected", "err", err)
		s.fail(w, r, http.StatusForbidden, "Login failed.")
		return
	}
	var cl claims
	if err := idToken.Claims(&cl); err != nil {
		s.internalError(w, r, err)
		return
	}
	// some providers only return groups from the userinfo endpoint
	if cl.Groups == nil {
		info, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(token))
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		var extra claims
		if err := info.Claims(&extra); err != nil {
			s.internalError(w, r, err)
			return
		}
		if extra.Subject != cl.Subject {
			s.fail(w, r, http.StatusForbidden, "Login failed.")
			return
		}
		cl.Groups = extra.Groups
	}

	username := cl.Subject
	display := cl.Name
	if display == "" {
		display = cl.PreferredUsername
	}
	if display == "" {
		display = username
	}
	sess := store.Session{
		Username:    username,
		DisplayName: display,
		IsAdmin:     s.cfg.AdminGroup != "" && slices.Contains(cl.Groups, s.cfg.AdminGroup),
		CSRFToken:   randomToken(),
	}
	sessionToken := randomToken()
	if err := s.store.CreateSession(ctx, sessionToken, sess); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.log.Info("login", "user", username, "admin", s.isAdmin(username, sess.IsAdmin))
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: sessionToken, Path: "/", MaxAge: int(maxSession.Seconds()), Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusFound)
}

// isAdmin combines the group membership seen at login with PG_ADMINS, which is
// checked on every request so env.sh changes apply to existing sessions.
func (s *Server) isAdmin(username string, inAdminGroup bool) bool {
	return inAdminGroup || (username != "" && slices.Contains(s.cfg.Admins, username))
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := s.store.DeleteSession(r.Context(), c.Value); err != nil {
			s.log.Error("logout", "err", err)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
