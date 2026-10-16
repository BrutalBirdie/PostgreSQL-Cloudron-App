package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"

	"pgpanel/internal/hba"
	"pgpanel/internal/scram"
	"pgpanel/internal/store"
)

var ownerPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type homeData struct {
	Roles []store.Role
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.RolesOwnedBy(r.Context(), sessionFrom(r).Username)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "home", homeData{Roles: roles})
}

type secretData struct {
	Role     string
	Database string
	Password string
}

// canManage: admins manage every tenant role, users only the roles assigned to them.
func canManage(sess *store.Session, role *store.Role) bool {
	return sess.IsAdmin || (role.Owner != "" && role.Owner == sess.Username)
}

func (s *Server) rotatePassword(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	role, err := s.store.GetRole(r.Context(), name)
	if err == nil && !canManage(sessionFrom(r), role) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.userError(w, r, err)
		return
	}
	password, err := s.setNewPassword(r.Context(), name)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	s.audit(r, "role.password", name, "")
	s.render(w, r, http.StatusOK, "secret", secretData{Role: name, Database: firstOr(role.Databases, name), Password: password})
}

func (s *Server) setNewPassword(ctx context.Context, role string) (string, error) {
	password, err := scram.Password()
	if err != nil {
		return "", err
	}
	verifier, err := scram.Verifier(password)
	if err != nil {
		return "", err
	}
	return password, s.store.SetPassword(ctx, role, verifier)
}

func (s *Server) deleteDatabase(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ctx := r.Context()
	db, err := s.store.GetDatabase(ctx, name)
	if err == nil {
		var role *store.Role
		role, err = s.store.GetRole(ctx, db.Owner)
		if err == nil && !canManage(sessionFrom(r), role) {
			err = store.ErrNotFound
		}
	}
	if err != nil {
		s.userError(w, r, err)
		return
	}
	if r.PostForm.Get("confirm") != name {
		s.userError(w, r, badInput("Type the database name to confirm the deletion."))
		return
	}
	if err := s.store.DropDatabase(ctx, name); err != nil {
		s.userError(w, r, err)
		return
	}
	s.audit(r, "database.drop", name, "owner="+db.Owner)
	http.Redirect(w, r, backTo(r), http.StatusSeeOther)
}

type adminData struct {
	Roles     []store.Role
	Databases []store.Database
	Allowlist string
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	roles, err := s.store.ListRoles(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	dbs, err := s.store.ListDatabases(ctx)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	list, errs := hba.ReadFile(s.cfg.AllowlistFile)
	for _, e := range errs {
		s.log.Warn("allowlist", "err", e)
	}
	var b strings.Builder
	for _, p := range list {
		b.WriteString(p.String() + "\n")
	}
	s.render(w, r, http.StatusOK, "admin", adminData{Roles: roles, Databases: dbs, Allowlist: b.String()})
}

func (s *Server) auditLog(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.ListAudit(r.Context(), 500)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "audit", entries)
}

func (s *Server) createRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := strings.TrimSpace(r.PostForm.Get("name"))
	owner := strings.TrimSpace(r.PostForm.Get("owner"))
	if owner != "" && !ownerPattern.MatchString(owner) {
		s.userError(w, r, badInput("Owner must be a Cloudron username."))
		return
	}
	limit, err := formInt(r, "conn_limit", 20, 1, 1000)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	maxDBs, err := formMaxDatabases(r, owner)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	password, err := scram.Password()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	verifier, err := scram.Verifier(password)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.store.CreateRole(ctx, name, verifier, limit, owner, maxDBs); err != nil {
		s.userError(w, r, err)
		return
	}
	s.audit(r, "role.create", name, fmt.Sprintf("owner=%s conn_limit=%d max_databases=%d", owner, limit, maxDBs))
	data := secretData{Role: name, Password: password}
	if r.PostForm.Get("with_database") == "on" {
		if err := s.store.CreateDatabase(ctx, name, name, 0); err != nil {
			s.userError(w, r, fmt.Errorf("role created, database failed: %w", err))
			return
		}
		s.audit(r, "database.create", name, "owner="+name)
		data.Database = name
	}
	s.render(w, r, http.StatusOK, "secret", data)
}

func (s *Server) updateRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	owner := strings.TrimSpace(r.PostForm.Get("owner"))
	if owner != "" && !ownerPattern.MatchString(owner) {
		s.userError(w, r, badInput("Owner must be a Cloudron username."))
		return
	}
	limit, err := formInt(r, "conn_limit", 20, 1, 1000)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	maxDBs, err := formMaxDatabases(r, owner)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	if err := s.store.UpdateRole(r.Context(), name, owner, limit, maxDBs); err != nil {
		s.userError(w, r, err)
		return
	}
	s.audit(r, "role.update", name, fmt.Sprintf("owner=%s conn_limit=%d max_databases=%d", owner, limit, maxDBs))
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) deleteRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if r.PostForm.Get("confirm") != name {
		s.userError(w, r, badInput("Type the role name to confirm the deletion."))
		return
	}
	if err := s.store.DropRole(r.Context(), name); err != nil {
		if errors.Is(err, store.ErrHasDatabases) {
			err = badInput(err.Error() + ". Delete them first.")
		}
		s.userError(w, r, err)
		return
	}
	s.audit(r, "role.drop", name, "")
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) createDatabase(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostForm.Get("name"))
	owner := r.PostForm.Get("owner")
	if err := s.store.CreateDatabase(r.Context(), name, owner, 0); err != nil {
		s.userError(w, r, err)
		return
	}
	s.audit(r, "database.create", name, "owner="+owner)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

// createOwnDatabase is the self-service path, limited by the role's max_databases.
func (s *Server) createOwnDatabase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	role, err := s.store.GetRole(ctx, r.PathValue("name"))
	if err == nil && (role.Owner == "" || role.Owner != sessionFrom(r).Username) {
		err = store.ErrNotFound
	}
	if err != nil {
		s.userError(w, r, err)
		return
	}
	if role.MaxDatabases < 1 {
		s.fail(w, r, http.StatusForbidden, "This role is not allowed to create databases. Ask an administrator.")
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if err := s.store.CreateDatabase(ctx, name, role.Name, role.MaxDatabases); err != nil {
		s.userError(w, r, err)
		return
	}
	s.audit(r, "database.create", name, fmt.Sprintf("owner=%s self-service", role.Name))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// formMaxDatabases returns 0 unless self-service database creation is enabled.
func formMaxDatabases(r *http.Request, owner string) (int, error) {
	if r.PostForm.Get("allow_create_db") != "on" {
		return 0, nil
	}
	if owner == "" {
		return 0, badInput("Creating databases needs an owner, set a Cloudron username.")
	}
	return formInt(r, "max_databases", 3, 1, 100)
}

// saveAllowlist validates every entry, writes the allowlist and pg_hba.conf, and
// only reloads PostgreSQL when the server accepts the new file.
func (s *Server) saveAllowlist(w http.ResponseWriter, r *http.Request) {
	var list []netip.Prefix
	var problems []string
	seen := map[netip.Prefix]bool{}
	for line := range strings.Lines(r.PostForm.Get("allowlist")) {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		p, err := hba.ParseEntry(line)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		if !seen[p] {
			seen[p] = true
			list = append(list, p)
		}
	}
	if len(problems) > 0 {
		s.userError(w, r, badInput("Nothing saved. "+strings.Join(problems, "; ")))
		return
	}
	if err := s.applyAllowlist(r.Context(), list); err != nil {
		s.userError(w, r, err)
		return
	}
	entries := make([]string, len(list))
	for i, p := range list {
		entries[i] = p.String()
	}
	s.audit(r, "allowlist.update", "pg_hba", strings.Join(entries, " "))
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) applyAllowlist(ctx context.Context, list []netip.Prefix) error {
	s.hbaMu.Lock()
	defer s.hbaMu.Unlock()

	oldAllow, err := os.ReadFile(s.cfg.AllowlistFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	oldHBA, err := os.ReadFile(s.cfg.HBAFile)
	if err != nil {
		return err
	}
	restore := func() {
		if err := hba.WriteFileAtomic(s.cfg.HBAFile, string(oldHBA), 0o644); err != nil {
			s.log.Error("restoring pg_hba.conf", "err", err)
		}
		if err := hba.WriteFileAtomic(s.cfg.AllowlistFile, string(oldAllow), 0o640); err != nil {
			s.log.Error("restoring allowlist", "err", err)
		}
	}

	if err := hba.WriteFileAtomic(s.cfg.AllowlistFile, hba.FormatAllowlist(list), 0o640); err != nil {
		return err
	}
	if err := hba.WriteFileAtomic(s.cfg.HBAFile, hba.Render(list, s.cfg.PGAdminPath != ""), 0o644); err != nil {
		restore()
		return err
	}
	problems, err := s.store.HBAErrors(ctx)
	if err == nil && len(problems) > 0 {
		err = badInput("PostgreSQL rejected the new rules, nothing changed: " + strings.Join(problems, "; "))
	}
	if err == nil {
		err = s.store.ReloadConfig(ctx)
	}
	if err != nil {
		restore()
		return err
	}
	return nil
}

func firstOr(list []string, def string) string {
	if len(list) > 0 {
		return list[0]
	}
	return def
}

// backTo only allows the two known pages, never a user supplied URL.
func backTo(r *http.Request) string {
	if r.PostForm.Get("back") == "admin" && sessionFrom(r).IsAdmin {
		return "/admin"
	}
	return "/"
}
