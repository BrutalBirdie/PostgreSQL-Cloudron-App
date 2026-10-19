package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"pgpanel/internal/access"
	"pgpanel/internal/directory"
	"pgpanel/internal/scram"
	"pgpanel/internal/store"
)

type memberKey struct{}

func memberFrom(r *http.Request) access.Member {
	m, _ := r.Context().Value(memberKey{}).(access.Member)
	return m
}

// canManage: admins manage every role, users the roles they own by name or
// through a group.
func canManage(r *http.Request, role *store.Role) bool {
	return sessionFrom(r).IsAdmin || access.Owns(role.Owners, memberFrom(r))
}

// owns is canManage without the admin shortcut, for pages about the user's own roles.
func owns(r *http.Request, role *store.Role) bool {
	return access.Owns(role.Owners, memberFrom(r))
}

// roleSheet is a role with what its settings sheet shows.
type roleSheet struct {
	store.Role
	Mine       bool         // the user owns the role
	Login      *store.Login // the user's own login, nil until created
	Logins     []store.Login
	OwnersText string
}

// roleSheet loads the user's own login and, for the admin view, all logins.
func (s *Server) roleSheet(r *http.Request, role store.Role, admin bool) (roleSheet, error) {
	ctx := r.Context()
	sheet := roleSheet{Role: role, Mine: owns(r, &role), OwnersText: ownersText(role.Owners)}
	if sheet.Mine {
		l, err := s.store.LoginOf(ctx, role.Name, sessionFrom(r).Username)
		switch {
		case err == nil:
			sheet.Login = l
		case !errors.Is(err, store.ErrNotFound):
			return sheet, err
		}
	}
	if admin {
		var err error
		if sheet.Logins, err = s.store.ListLogins(ctx, role.Name); err != nil {
			return sheet, err
		}
	}
	return sheet, nil
}

type homeData struct {
	Roles []roleSheet
	Stats map[string]store.DatabaseStats
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	roles, err := s.store.RolesOwnedBy(ctx, memberFrom(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	views := make([]roleSheet, len(roles))
	for i, role := range roles {
		var err error
		if views[i], err = s.roleSheet(r, role, false); err != nil {
			s.internalError(w, r, err)
			return
		}
	}
	stats, err := s.store.DatabaseStats(ctx, "")
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "home", homeData{Roles: views, Stats: stats})
}

type secretData struct {
	Login    string
	Role     string
	Database string
	Password string
}

// setMyPassword creates the user's own login for a role or gives it a new
// password. Other users' logins of the role are not affected.
func (s *Server) setMyPassword(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	role, err := s.store.GetRole(ctx, r.PathValue("name"))
	if err == nil && !canManage(r, role) {
		err = store.ErrNotFound
	}
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
	login, err := s.store.SetLoginPassword(ctx, role.Name, sessionFrom(r).Username, verifier, role.ConnLimit)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	if err := s.WriteAppPasswordMap(ctx); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, "login.password", login, "role="+role.Name)
	db := role.Name
	if len(role.Databases) > 0 {
		db = role.Databases[0]
	}
	s.render(w, r, http.StatusOK, "secret", secretData{Login: login, Role: role.Name, Database: db, Password: password})
}

// parseOwners reads the owners field: "user:name" and "group:name" separated
// by commas or new lines. Users and groups are checked against the directory.
func (s *Server) parseOwners(ctx context.Context, text string) ([]access.Principal, error) {
	var owners []access.Principal
	seen := map[string]bool{}
	for _, token := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		kind, name, ok := strings.Cut(token, ":")
		if !ok {
			kind, name = access.KindUser, token
		}
		kind, name = strings.ToLower(strings.TrimSpace(kind)), strings.TrimSpace(name)
		var p access.Principal
		switch kind {
		case access.KindUser:
			user, err := s.cfg.Directory.Lookup(ctx, name)
			switch {
			case errors.Is(err, directory.ErrNotConfigured):
				if !usernamePattern.MatchString(name) {
					return nil, badInput(fmt.Sprintf("%q is not a valid Cloudron username.", name))
				}
				p = access.Principal{Kind: access.KindUser, ID: name, Display: name}
			case err != nil:
				return nil, err
			case user == nil:
				return nil, badInput(fmt.Sprintf("There is no Cloudron user %q with access to this app.", name))
			default:
				p = access.Principal{Kind: access.KindUser, ID: user.Username, Display: displayOf(user)}
			}
		case access.KindGroup:
			g, err := s.cfg.Directory.GroupByName(ctx, name)
			if errors.Is(err, directory.ErrNotConfigured) {
				return nil, badInput("Groups need the SCIM addon.")
			}
			if err != nil {
				return nil, err
			}
			if g == nil {
				return nil, badInput(fmt.Sprintf("There is no Cloudron group %q with access to this app.", name))
			}
			p = access.Principal{Kind: access.KindGroup, ID: g.ID, Display: g.Name}
		default:
			return nil, badInput(fmt.Sprintf("Unknown owner %q, use user:name or group:name.", token))
		}
		if key := p.Kind + ":" + p.ID; !seen[key] {
			seen[key] = true
			owners = append(owners, p)
		}
	}
	return owners, nil
}

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

func displayOf(u *directory.User) string {
	if u.DisplayName != "" && u.DisplayName != u.Username {
		return u.Username + " (" + u.DisplayName + ")"
	}
	return u.Username
}

// ownersText turns owners back into the owners field.
func ownersText(owners []access.Principal) string {
	parts := make([]string, len(owners))
	for i, p := range owners {
		name := p.ID
		if p.Kind == access.KindGroup {
			name = p.Display
		}
		parts[i] = p.Kind + ":" + name
	}
	return strings.Join(parts, ", ")
}

type principalJSON struct {
	Kind  string `json:"kind"`
	Name  string `json:"name"`
	Label string `json:"label"`
}

// principals lists users and groups for the owner picker (admins only).
func (s *Server) principals(w http.ResponseWriter, r *http.Request) {
	users, groups, err := s.cfg.Directory.Directory(r.Context())
	if err != nil && !errors.Is(err, directory.ErrNotConfigured) {
		s.log.Error("reading the directory", "err", err)
		http.Error(w, "directory not reachable", http.StatusBadGateway)
		return
	}
	list := []principalJSON{}
	for _, u := range users {
		list = append(list, principalJSON{Kind: access.KindUser, Name: u.Username, Label: displayOf(&u)})
	}
	for _, g := range groups {
		list = append(list, principalJSON{Kind: access.KindGroup, Name: g.Name, Label: g.Name})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}

func (s *Server) createRole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name := strings.TrimSpace(r.PostForm.Get("name"))
	owners, err := s.parseOwners(ctx, r.PostForm.Get("owners"))
	if err != nil {
		s.userError(w, r, err)
		return
	}
	limit, err := formInt(r, "conn_limit", 20, 1, 1000)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	maxDBs, err := formMaxDatabases(r, len(owners))
	if err != nil {
		s.userError(w, r, err)
		return
	}
	if err := s.store.CreateRole(ctx, name, limit, owners, maxDBs); err != nil {
		s.userError(w, r, err)
		return
	}
	s.audit(r, "role.create", name, fmt.Sprintf("owners=%s conn_limit=%d max_databases=%d", ownersText(owners), limit, maxDBs))
	if r.PostForm.Get("with_database") == "on" {
		if err := s.store.CreateDatabase(ctx, name, name, 0); err != nil {
			s.userError(w, r, fmt.Errorf("role created, database failed: %w", err))
			return
		}
		s.audit(r, "database.create", name, "owner="+name)
	}
	http.Redirect(w, r, roleSheetURL(name), http.StatusSeeOther)
}

// rolePage is the old address of the role settings, they are a sheet on the roles tab now.
func (s *Server) rolePage(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, roleSheetURL(r.PathValue("name")), http.StatusSeeOther)
}

func roleSheetURL(name string) string { return "/admin/roles#sheet-role-" + name }

func (s *Server) updateRole(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	owners, err := s.parseOwners(r.Context(), r.PostForm.Get("owners"))
	if err != nil {
		s.userError(w, r, err)
		return
	}
	limit, err := formInt(r, "conn_limit", 20, 1, 1000)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	maxDBs, err := formMaxDatabases(r, len(owners))
	if err != nil {
		s.userError(w, r, err)
		return
	}
	if err := s.store.UpdateRole(r.Context(), name, owners, limit, maxDBs); err != nil {
		s.userError(w, r, err)
		return
	}
	s.audit(r, "role.update", name, fmt.Sprintf("owners=%s conn_limit=%d max_databases=%d", ownersText(owners), limit, maxDBs))
	http.Redirect(w, r, roleSheetURL(name), http.StatusSeeOther)
}

func (s *Server) revokeLogin(w http.ResponseWriter, r *http.Request) {
	name, login := r.PathValue("name"), r.PathValue("login")
	logins, err := s.store.ListLogins(r.Context(), name)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	found := false
	for _, l := range logins {
		found = found || l.LoginRole == login
	}
	if !found {
		s.userError(w, r, store.ErrNotFound)
		return
	}
	if err := s.store.RevokeLogin(r.Context(), login); err != nil {
		s.userError(w, r, err)
		return
	}
	if err := s.WriteAppPasswordMap(r.Context()); err != nil {
		s.log.Error("writing the app password map", "err", err)
	}
	s.audit(r, "login.revoke", login, "role="+name)
	http.Redirect(w, r, roleSheetURL(name), http.StatusSeeOther)
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
	if err := s.store.DeleteUploadsOf(r.Context(), name); err != nil {
		s.log.Error("deleting upload records of dropped role", "role", name, "err", err)
	}
	if err := os.RemoveAll(s.uploadDir(name)); err != nil {
		s.log.Error("deleting uploads of dropped role", "role", name, "err", err)
	}
	http.Redirect(w, r, "/admin/roles", http.StatusSeeOther)
}

// createOwnDatabase is the self-service path for owners, limited by the role's max_databases.
func (s *Server) createOwnDatabase(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	role, err := s.store.GetRole(ctx, r.PathValue("name"))
	if err == nil && !owns(r, role) {
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
func formMaxDatabases(r *http.Request, owners int) (int, error) {
	if r.PostForm.Get("allow_create_db") != "on" {
		return 0, nil
	}
	if owners == 0 {
		return 0, badInput("Creating databases needs at least one owner.")
	}
	return formInt(r, "max_databases", 3, 1, 100)
}

// afterDelete returns to "My databases" for an owner, admins deleting another
// user's database return to the admin page.
func (s *Server) afterDelete(r *http.Request, db *store.Database) string {
	if !sessionFrom(r).IsAdmin {
		return "/"
	}
	role, err := s.store.GetRole(r.Context(), db.Owner)
	if err == nil && owns(r, role) {
		return "/"
	}
	return "/admin/databases"
}
