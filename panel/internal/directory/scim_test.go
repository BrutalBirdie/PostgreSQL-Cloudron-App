package directory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func mockSCIM(t *testing.T, users []map[string]any, groups []map[string]any) (*httptest.Server, *atomic.Int32, *atomic.Bool) {
	var calls atomic.Int32
	var down atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if down.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		var list []map[string]any
		switch r.URL.Path {
		case "/v2/Users":
			list = users
			if f := r.URL.Query().Get("filter"); f != "" {
				name := strings.TrimSuffix(strings.TrimPrefix(f, `userName eq "`), `"`)
				list = nil
				for _, u := range users {
					if u["userName"] == name {
						list = append(list, u)
					}
				}
			}
		case "/v2/Groups":
			list = groups
		}
		start := 1
		if s := r.URL.Query().Get("startIndex"); s != "" {
			json.Unmarshal([]byte(s), &start)
		}
		page := list[min(start-1, len(list)):min(start-1+2, len(list))] // page size 2 to test paging
		json.NewEncoder(w).Encode(map[string]any{"totalResults": len(list), "Resources": page})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, &down
}

func TestLookupAndCache(t *testing.T) {
	srv, calls, down := mockSCIM(t, []map[string]any{
		{"userName": "carol", "active": true, "groups": []map[string]any{{"value": "g1", "display": "dbteam"}},
			"emails": []map[string]any{{"value": "old@example.test"}, {"value": "carol@example.test", "primary": true}}},
		{"userName": "gone", "active": false},
	}, nil)
	c := New(srv.URL, "tok", time.Hour)
	ctx := context.Background()

	u, err := c.Lookup(ctx, "carol")
	if err != nil || u == nil || u.GroupIDs[0] != "g1" || u.GroupNames[0] != "dbteam" || u.Email != "carol@example.test" {
		t.Fatalf("carol: %+v %v", u, err)
	}
	before := calls.Load()
	c.Lookup(ctx, "carol")
	if calls.Load() != before {
		t.Error("second lookup was not cached")
	}
	if u, err := c.Lookup(ctx, "gone"); u != nil || err != nil {
		t.Errorf("inactive user: %+v %v", u, err)
	}
	if u, err := c.Lookup(ctx, "nobody"); u != nil || err != nil {
		t.Errorf("unknown user: %+v %v", u, err)
	}

	short := New(srv.URL, "tok", time.Nanosecond)
	short.Lookup(ctx, "carol")
	down.Store(true)
	u, err = short.Lookup(ctx, "carol")
	if err == nil || u == nil || u.Username != "carol" {
		t.Fatalf("SCIM down must return the last known user with the error: %+v %v", u, err)
	}
	if u, err := short.Lookup(ctx, "neverseen"); u != nil || err == nil {
		t.Fatalf("SCIM down without cache must return an error and no user: %+v %v", u, err)
	}
}

func TestDirectoryPaging(t *testing.T) {
	srv, _, _ := mockSCIM(t, []map[string]any{
		{"userName": "a", "active": true}, {"userName": "b", "active": true}, {"userName": "c", "active": true}, {"userName": "d", "active": false},
	}, []map[string]any{{"id": "g1", "displayName": "dbteam"}, {"id": "g2", "displayName": "ops"}, {"id": "g3", "displayName": "PgAdmins"}})
	c := New(srv.URL, "tok", time.Hour)
	users, groups, err := c.Directory(context.Background())
	if err != nil || len(users) != 3 || len(groups) != 3 {
		t.Fatalf("users %v groups %v err %v", users, groups, err)
	}
	g, err := c.GroupByName(context.Background(), "pgadmins")
	if err != nil || g == nil || g.ID != "g3" {
		t.Fatalf("group by name: %+v %v", g, err)
	}
}

func TestNotConfigured(t *testing.T) {
	var c *Client = New("", "", time.Minute)
	if _, err := c.Lookup(context.Background(), "x"); err != ErrNotConfigured {
		t.Fatal(err)
	}
}
