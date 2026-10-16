// Package access decides who may manage a role. The panel uses it for every
// request, the worker to revoke logins of users who lost access.
package access

import "slices"

// Principal is an owner of a role: a Cloudron user (ID is the username) or a
// Cloudron group (ID is the SCIM group id, Display its current name).
type Principal struct {
	Kind    string // "user" or "group"
	ID      string
	Display string
}

const (
	KindUser  = "user"
	KindGroup = "group"
)

// Member is what the directory knows about a user.
type Member struct {
	Username   string
	GroupIDs   []string
	GroupNames []string
}

// Admins configures who is a panel admin: usernames from PG_ADMINS and group
// names from PG_ADMIN_GROUP.
type Admins struct {
	Users  []string
	Groups []string
}

func (a Admins) IsAdmin(m Member) bool {
	if m.Username == "" {
		return false
	}
	if slices.Contains(a.Users, m.Username) {
		return true
	}
	for _, g := range m.GroupNames {
		if slices.Contains(a.Groups, g) {
			return true
		}
	}
	return false
}

// Owns reports whether the member is one of the owners, by name or through a group.
func Owns(owners []Principal, m Member) bool {
	if m.Username == "" {
		return false
	}
	for _, p := range owners {
		switch p.Kind {
		case KindUser:
			if p.ID == m.Username {
				return true
			}
		case KindGroup:
			if slices.Contains(m.GroupIDs, p.ID) {
				return true
			}
		}
	}
	return false
}
