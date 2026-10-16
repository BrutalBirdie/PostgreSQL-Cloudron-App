package worker

import (
	"context"
	"time"

	"pgpanel/internal/access"
	"pgpanel/internal/store"
)

// AccessSync revokes the logins of users who may no longer manage the role:
// removed as owner, removed from an owner group, removed from the app or
// deleted in Cloudron. It runs every interval and when the panel asks for it.
// When the directory cannot be read nothing is revoked, a SCIM outage must not
// lock out every client.
func (w *Worker) AccessSync(ctx context.Context, interval time.Duration) {
	var last time.Time
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		requested, err := w.store.TakeAccessSyncRequest(ctx)
		if err != nil && ctx.Err() == nil {
			w.log.Error("reading access sync request", "err", err)
		}
		if requested || time.Since(last) >= interval {
			w.syncLogins(ctx)
			last = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (w *Worker) syncLogins(ctx context.Context) {
	logins, err := w.store.ListLogins(ctx, "")
	if err != nil {
		w.log.Error("listing logins", "err", err)
		return
	}
	if len(logins) == 0 {
		return
	}
	roles, err := w.store.ListRoles(ctx)
	if err != nil {
		w.log.Error("listing roles", "err", err)
		return
	}
	byName := map[string]store.Role{}
	for _, r := range roles {
		byName[r.Name] = r
	}
	directoryDown := false
	for _, l := range logins {
		role, roleExists := byName[l.RoleName]
		reason := ""
		switch {
		case !roleExists:
			reason = "role deleted"
		case l.Revoked:
			reason = "revoked in the panel"
		case directoryDown:
			continue
		default:
			user, err := w.cfg.Directory.Lookup(ctx, l.Username)
			if err != nil {
				w.log.Warn("cannot check logins, the directory is not reachable, nothing revoked", "err", err)
				directoryDown = true
				continue
			}
			m := access.Member{Username: l.Username}
			if user != nil {
				m = user.Member()
			}
			switch {
			case user == nil:
				reason = "user deleted or removed from the app"
			case !access.Owns(role.Owners, m) && !w.cfg.Admins.IsAdmin(m):
				reason = "no longer an owner of the role"
			}
		}
		if reason == "" {
			continue
		}
		if err := w.store.RemoveLogin(ctx, l.LoginRole, l.RoleName); err != nil {
			w.log.Error("removing login", "login", l.LoginRole, "err", err)
			continue
		}
		w.log.Info("login removed", "login", l.LoginRole, "user", l.Username, "reason", reason)
		if err := w.store.Audit(ctx, store.AuditEntry{Actor: "access sync", Action: "login.remove", Target: l.LoginRole, Detail: reason}); err != nil {
			w.log.Error("audit write failed", "err", err)
		}
	}
}
