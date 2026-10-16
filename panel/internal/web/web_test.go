package web

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"pgpanel/internal/store"
)

func testServer(t *testing.T) *Server {
	s, err := New(Config{Origin: "https://pg.example", PublicHost: "pg.example", PublicPort: "5432", AdminGroup: "postgres-admins", Admins: []string{"root_user"}}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPagesRender(t *testing.T) {
	s := testServer(t)
	admin := &store.Session{Username: "ann", DisplayName: "Ann", IsAdmin: true, CSRFToken: "tok"}
	roles := []store.Role{{Name: "app_one", ConnLimit: 20, Owner: "ann", MaxDatabases: 3, Databases: []string{"app_one"}}}
	pages := map[string]any{
		"login":  nil,
		"home":   homeData{Roles: roles},
		"admin":  adminData{Roles: roles, Databases: []store.Database{{Name: "app_one", Owner: "app_one"}}, Allowlist: "203.0.113.10/32\n"},
		"secret": secretData{Role: "app_one", Database: "app_one", Password: "pw"},
		"audit":  []store.AuditEntry{{At: time.Now(), Actor: "ann", Action: "role.create", Target: "app_one"}},
		"error":  nil,
	}
	for page, data := range pages {
		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, admin))
		rec := httptest.NewRecorder()
		s.render(rec, req, http.StatusOK, page, data)
		body := rec.Body.String()
		if !strings.Contains(body, "</html>") {
			t.Errorf("%s: incomplete page: %s", page, body)
		}
		if page != "login" && !strings.Contains(body, `value="tok"`) {
			t.Errorf("%s: csrf token missing in logout form", page)
		}
	}
}

func TestConnURL(t *testing.T) {
	s := testServer(t)
	got := s.connURL("app_one", "app_one")
	want := "postgresql://app_one@pg.example:5432/app_one?sslmode=verify-full&sslrootcert=system"
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestValidPost(t *testing.T) {
	s := testServer(t)
	sess := &store.Session{CSRFToken: "tok"}
	cases := []struct {
		name   string
		body   string
		origin string
		site   string
		want   bool
	}{
		{"valid", "csrf=tok", "https://pg.example", "same-origin", true},
		{"no headers", "csrf=tok", "", "", true},
		{"wrong token", "csrf=nope", "https://pg.example", "same-origin", false},
		{"missing token", "x=1", "", "", false},
		{"foreign origin", "csrf=tok", "https://evil.example", "", false},
		{"cross site", "csrf=tok", "", "cross-site", false},
		{"opaque origin", "csrf=tok", "null", "same-origin", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest("POST", "/admin/roles", strings.NewReader(c.body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if c.origin != "" {
			req.Header.Set("Origin", c.origin)
		}
		if c.site != "" {
			req.Header.Set("Sec-Fetch-Site", c.site)
		}
		if got := s.validPost(httptest.NewRecorder(), req, sess); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestCanManage(t *testing.T) {
	role := &store.Role{Name: "r", Owner: "bob"}
	if !canManage(&store.Session{Username: "bob"}, role) {
		t.Error("owner must manage own role")
	}
	if canManage(&store.Session{Username: "eve"}, role) {
		t.Error("other user must not manage the role")
	}
	if canManage(&store.Session{Username: ""}, &store.Role{Name: "r"}) {
		t.Error("unassigned role must not match an empty username")
	}
	if !canManage(&store.Session{Username: "ann", IsAdmin: true}, role) {
		t.Error("admin must manage every role")
	}
}

func TestIsAdmin(t *testing.T) {
	s := testServer(t)
	cases := []struct {
		user    string
		inGroup bool
		want    bool
	}{
		{"root_user", false, true},
		{"ann", true, true},
		{"bob", false, false},
		{"", false, false},
	}
	for _, c := range cases {
		if got := s.isAdmin(c.user, c.inGroup); got != c.want {
			t.Errorf("%s %v: got %v want %v", c.user, c.inGroup, got, c.want)
		}
	}
}
