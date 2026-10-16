package access

import "testing"

func TestOwns(t *testing.T) {
	owners := []Principal{{Kind: KindUser, ID: "bob"}, {Kind: KindGroup, ID: "gid-team", Display: "dbteam"}}
	cases := []struct {
		m    Member
		want bool
	}{
		{Member{Username: "bob"}, true},
		{Member{Username: "carol", GroupIDs: []string{"gid-team"}}, true},
		{Member{Username: "eve", GroupIDs: []string{"gid-other"}, GroupNames: []string{"dbteam"}}, false}, // group matched by id, not name
		{Member{Username: "", GroupIDs: []string{"gid-team"}}, false},
		{Member{Username: "dbteam"}, false},
	}
	for _, c := range cases {
		if got := Owns(owners, c.m); got != c.want {
			t.Errorf("%+v: got %v want %v", c.m, got, c.want)
		}
	}
	if Owns(nil, Member{Username: "bob"}) {
		t.Error("no owners must not match")
	}
}

func TestIsAdmin(t *testing.T) {
	a := Admins{Users: []string{"root"}, Groups: []string{"postgres-admins", "PgAdmins"}}
	cases := []struct {
		m    Member
		want bool
	}{
		{Member{Username: "root"}, true},
		{Member{Username: "ann", GroupNames: []string{"PgAdmins"}}, true},
		{Member{Username: "bob", GroupNames: []string{"staff"}}, false},
		{Member{Username: "", GroupNames: []string{"PgAdmins"}}, false},
	}
	for _, c := range cases {
		if got := a.IsAdmin(c.m); got != c.want {
			t.Errorf("%+v: got %v want %v", c.m, got, c.want)
		}
	}
}
