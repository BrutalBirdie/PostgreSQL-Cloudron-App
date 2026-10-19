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

	"pgpanel/internal/access"
	"pgpanel/internal/store"
)

func testServer(t *testing.T) *Server {
	s, err := New(Config{Origin: "https://pg.example", PublicHost: "pg.example", PublicPort: "5432", BridgeOrigin: "http://172.18.0.1:3006", DashboardURL: "https://my.example", Admins: access.Admins{Users: []string{"root_user"}, Groups: []string{"postgres-admins"}}}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPagesRender(t *testing.T) {
	s := testServer(t)
	now, pct := time.Now(), 42
	snapID := int64(7)
	admin := &store.Session{Username: "ann", DisplayName: "Ann Admin", IsAdmin: true, CSRFToken: "tok"}
	roles := []store.Role{{Name: "app_one", ConnLimit: 20, Owners: []access.Principal{{Kind: "user", ID: "ann", Display: "ann"}, {Kind: "group", ID: "g1", Display: "dbteam"}}, MaxDatabases: 3, Databases: []string{"app_one"}}}
	login := &store.Login{LoginRole: "app_one.ann", RoleName: "app_one", Username: "ann", Auth: store.AuthPassword, RotatedAt: time.Now()}
	apppwLogin := &store.Login{LoginRole: "app_one.ann", RoleName: "app_one", Username: "ann", Auth: store.AuthAppPassword, RotatedAt: time.Now()}
	sheets := []roleSheet{{Role: roles[0], Mine: true, Login: login, Logins: []store.Login{*login}, OwnersText: "user:ann, group:dbteam"}, {Role: roles[0], Mine: true}, {Role: roles[0], Mine: true, Login: apppwLogin}}
	snap := store.Snapshot{ID: 7, Database: "app_one", OwnerRole: "app_one", Kind: store.KindPreRestore, SizeBytes: 123456, CreatedBy: "ann", CreatedAt: time.Now(), Note: "automatic"}
	running := store.Job{ID: 2, Kind: "restore", SnapshotID: &snapID, Status: "running", CreatedAt: time.Now(), StartedAt: &now, Progress: &pct, Step: `Processing data for table "public.t"`, RequestedBy: "ann"}
	type page struct {
		name string
		data any
		want []string
	}
	pages := []page{
		{"login", nil, []string{"Sign in with Cloudron"}},
		{"home", homeData{Roles: sheets, Stats: map[string]store.DatabaseStats{"app_one": {SizeBytes: 7 << 20}}},
			[]string{`action="/roles/app_one/apppw"`, "Cloudron app password", `href="https://my.example/#/profile"`, "7.0 MiB", `data-copy="postgresql://app_one.ann@pg.example:5432/app_one?sslmode=verify-full&amp;sslrootcert=system"`, `popovertarget="sheet-role-app_one"`, `id="sheet-newdb-app_one"`}},
		{"secret", secretData{Login: "app_one.ann", Role: "app_one", Database: "app_one", Password: "pw"}, []string{`data-copy="pw"`, `<code class="secret"`}},
		{"error", nil, []string{"Something went wrong"}},
		{"uploads", uploadsData{Role: roles[0], Roles: []string{"app_one"}, KeepDays: 8, Uploads: []uploadView{
			{Upload: store.Upload{ID: 1, FileName: "a.dump", SizeBytes: 10, FirstSeen: time.Now(), SHA256: "ab", VerifiedBy: "browser"}, Format: "custom"},
			{Upload: store.Upload{ID: 3, FileName: "c.dump", SizeBytes: 10, FirstSeen: time.Now(), SHA256: "ab"}, Format: "custom"},
			{Upload: store.Upload{ID: 2, FileName: "b.sql", Keep: true, FirstSeen: time.Now()}, FormatErr: "plain SQL"},
		}}, []string{`id="sheet-import-1"`, `action="/uploads/3/verify"`, `aria-pressed="true"`}},
		{"database", databaseData{
			Database: store.Database{Name: "app_one", Owner: "app_one"}, Role: roles[0], URL: "postgresql://x",
			Snapshots: []store.Snapshot{snap}, Jobs: []store.Job{running, {ID: 1, Kind: "import", Status: "failed", Error: "boom", CreatedAt: time.Now()}}, Active: &running, JobKey: "2:running",
			MaxSnapshots: 7, Schedule: &store.Schedule{Database: "app_one", OwnerRole: "app_one", Cron: "0 3 * * *", NextRun: time.Now()}, Presets: cronPresets, Preset: "0 3 * * *",
			Stats: store.DatabaseStats{SizeBytes: 7 << 20, Snapshots: 1, LastSnapshot: &now}, Back: "/", BackLabel: "My databases",
		}, []string{`<progress id="job-bar" max="100" value="42"`, "Restore of #7", `data-key="2:running"`, `value="0 3 * * *" checked`, `id="sheet-restore-7"`, "before restore", "boom"}},
	}
	adminBase := adminData{Tabs: adminTabs, Roles: sheets[:1], Databases: []store.Database{{Name: "app_one", Owner: "app_one"}}, Allowlist: "203.0.113.10/32\n",
		Stats: map[string]store.DatabaseStats{"app_one": {SizeBytes: 7 << 20, Snapshots: 2}}, Disk: &diskUsage{Used: 1 << 30, Size: 4 << 30}, MaxConnections: "100",
		NotifyTo: "dba@example.test", MailReady: true, TestSent: true, OptIns: 1, ClientIP: "192.0.2.4",
		Params: []paramView{{Name: "work_mem", Value: "8MB", Running: "8MB", Default: "4MB"}, {Name: "max_connections", Running: "100", Restart: true, Pending: true}}, RestartPending: true,
		Connections: []store.Connection{{PID: 1, Database: "app_one", Login: "app_one.ann", ClientAddr: "192.0.2.4", State: "idle in transaction", BackendStart: now, StateChange: &now, TLSVersion: "TLSv1.3"}},
		Snapshots: []store.Snapshot{snap}, Filters: []filterOption{{"", "All", false}, {"db:app_one", "app_one", true}}, Filter: "db:app_one",
		Audit: []store.AuditEntry{{At: time.Now(), Actor: "ann", Action: "role.create", Target: "app_one"}}}
	adminWant := map[string][]string{
		"overview": {`href="/admin/connections"`, "of 100 allowed", `value="25"`}, "connections": {"idle in transaction", "192.0.2.4"}, "snapshots": {`href="/databases/app_one"`, `aria-current="page">app_one`},
		"roles": {`id="sheet-role-app_one"`, `action="/admin/roles/app_one/update"`, "user:ann, group:dbteam"}, "databases": {`class="rowlink" href="/databases/app_one"`},
		"network": {"203.0.113.10/32", "192.0.2.4"}, "notifications": {`value="dba@example.test"`, "1 user has"}, "server": {`name="work_mem"`, "restart pending"}, "audit": {"role.create"},
	}
	for view, want := range adminWant {
		d := adminBase
		d.View, d.Tab = view, adminViews[view]
		pages = append(pages, page{"admin", d, want})
	}
	for _, p := range pages {
		req := httptest.NewRequest("GET", "/", nil)
		req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, admin))
		rec := httptest.NewRecorder()
		s.render(rec, req, http.StatusOK, p.name, p.data)
		body := rec.Body.String()
		if !strings.Contains(body, "</html>") {
			t.Errorf("%s: incomplete page: %s", p.name, body)
			continue
		}
		for _, w := range p.want {
			if !strings.Contains(body, w) {
				t.Errorf("%s %v: %q missing", p.name, p.data != nil, w)
			}
		}
		if p.name != "login" && !strings.Contains(body, `value="tok"`) {
			t.Errorf("%s: csrf token missing in logout form", p.name)
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

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 1536: "1.5 KiB", 5 << 30: "5.0 GiB"} {
		if got := humanBytes(n); got != want {
			t.Errorf("%d: got %s want %s", n, got, want)
		}
	}
}

func TestCanManage(t *testing.T) {
	role := &store.Role{Name: "r", Owners: []access.Principal{{Kind: "user", ID: "bob"}, {Kind: "group", ID: "g1"}}}
	req := func(sess *store.Session, m access.Member) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		ctx := context.WithValue(r.Context(), ctxKey{}, sess)
		return r.WithContext(context.WithValue(ctx, memberKey{}, m))
	}
	cases := []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"named owner", req(&store.Session{Username: "bob"}, access.Member{Username: "bob"}), true},
		{"group member", req(&store.Session{Username: "carol"}, access.Member{Username: "carol", GroupIDs: []string{"g1"}}), true},
		{"stranger", req(&store.Session{Username: "eve"}, access.Member{Username: "eve", GroupIDs: []string{"g2"}}), false},
		{"admin", req(&store.Session{Username: "ann", IsAdmin: true}, access.Member{Username: "ann"}), true},
	}
	for _, c := range cases {
		if got := canManage(c.r, role); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	if owns(req(&store.Session{Username: "ann", IsAdmin: true}, access.Member{Username: "ann"}), role) {
		t.Error("admin must not count as owner")
	}
}

func TestParseOwnersWithoutDirectory(t *testing.T) {
	s := testServer(t)
	owners, err := s.parseOwners(context.Background(), "user:bob, carol\nuser:bob")
	if err != nil || len(owners) != 2 || owners[1].ID != "carol" {
		t.Fatalf("owners %v err %v", owners, err)
	}
	for _, bad := range []string{"group:dbteam", "user:Bad Name", "robot:x"} {
		if _, err := s.parseOwners(context.Background(), bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got := ownersText([]access.Principal{{Kind: "user", ID: "bob"}, {Kind: "group", ID: "g1", Display: "dbteam"}}); got != "user:bob, group:dbteam" {
		t.Errorf("ownersText = %q", got)
	}
}
