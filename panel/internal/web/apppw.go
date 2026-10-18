package web

import (
	"context"
	"net/http"

	"pgpanel/internal/apppw"
	"pgpanel/internal/store"
)

func (s *Server) appPasswordsEnabled() bool { return s.cfg.BridgeOrigin != "" }

// WriteAppPasswordMap writes the logins that use app passwords for the PAM
// helper. Called at start and after every change of a login's method.
func (s *Server) WriteAppPasswordMap(ctx context.Context) error {
	if s.cfg.AppPWMap == "" {
		return nil
	}
	s.appPWMu.Lock()
	defer s.appPWMu.Unlock()
	logins := map[string]string{}
	if s.appPasswordsEnabled() {
		var err error
		if logins, err = s.store.AppPasswordLogins(ctx); err != nil {
			return err
		}
	}
	return apppw.WriteMap(s.cfg.AppPWMap, apppw.Map{Bridge: s.cfg.BridgeOrigin, Logins: logins})
}

// useAppPassword switches the user's own login for a role to Cloudron app
// passwords, creating the login if needed. Its generated password stops working.
func (s *Server) useAppPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if !s.appPasswordsEnabled() {
		s.userError(w, r, badInput("App passwords need a newer Cloudron version."))
		return
	}
	role, err := s.store.GetRole(ctx, r.PathValue("name"))
	if err == nil && !canManage(r, role) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.userError(w, r, err)
		return
	}
	login, err := s.store.UseAppPassword(ctx, role.Name, sessionFrom(r).Username, role.ConnLimit)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	if err := s.WriteAppPasswordMap(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, "login.apppw", login, "role="+role.Name)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
