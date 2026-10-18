package web

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"syscall"

	"pgpanel/internal/hba"
	"pgpanel/internal/notify"
	"pgpanel/internal/store"
	"pgpanel/internal/worker"
)

func (s *Server) deleteDatabase(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ctx := r.Context()
	db, err := s.authorizeDatabase(r, name)
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
	if err := s.store.DeleteSchedule(ctx, name); err != nil {
		s.log.Error("deleting schedule of dropped database", "database", name, "err", err)
	}
	files, err := s.store.DeleteSnapshotsOf(ctx, name)
	if err != nil {
		s.log.Error("deleting snapshots of dropped database", "database", name, "err", err)
	}
	worker.RemoveFiles(s.cfg.SnapshotDir, files, s.log)
	if dir, err := worker.Resolve(s.cfg.SnapshotDir, name); err == nil {
		os.Remove(dir)
	}
	http.Redirect(w, r, s.afterDelete(r, db), http.StatusSeeOther)
}

type adminData struct {
	Roles     []store.Role
	Databases []store.Database
	Allowlist string
	Stats     map[string]store.DatabaseStats
	Total     store.DatabaseStats
	Disk      *diskUsage // nil when the volume cannot be read
	NotifyTo  string
	MailReady bool
	TestSent  bool
}

type diskUsage struct {
	Used, Size int64
}

func diskUsageOf(path string) (*diskUsage, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return nil, err
	}
	size := int64(st.Blocks) * st.Bsize
	return &diskUsage{Used: size - int64(st.Bavail)*st.Bsize, Size: size}, nil
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
	stats, err := s.store.DatabaseStats(ctx, "")
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	var total store.DatabaseStats
	for _, st := range stats {
		total.SizeBytes += st.SizeBytes
		total.Connections += st.Connections
		total.Snapshots += st.Snapshots
		total.SnapshotBytes += st.SnapshotBytes
	}
	disk, err := diskUsageOf(s.cfg.SnapshotDir)
	if err != nil {
		s.log.Warn("reading disk usage", "err", err)
	}
	notifyTo, err := s.store.Setting(ctx, worker.SettingNotifyTo)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "admin", adminData{Roles: roles, Databases: dbs, Allowlist: b.String(), Stats: stats, Total: total, Disk: disk,
		NotifyTo: notifyTo, MailReady: s.cfg.Mailer != nil, TestSent: r.URL.Query().Get("mail") == "sent"})
}

// saveNotifications stores the admin addresses for failure mails, or sends a
// test mail to the addresses in the form.
func (s *Server) saveNotifications(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := notify.ParseList(r.PostForm.Get("notify_to"))
	if err != nil {
		s.userError(w, r, badInput(err.Error()))
		return
	}
	value := strings.Join(list, ", ")
	if r.PostForm.Get("action") == "test" {
		if len(list) == 0 {
			s.userError(w, r, badInput("Enter an address to send the test mail to."))
			return
		}
		if _, err := s.cfg.Mailer.Send(ctx, list, "PostgreSQL: test mail", "This is a test mail from the PostgreSQL panel at "+s.cfg.Origin+".\n"); err != nil {
			s.log.Error("sending test mail", "err", err)
			s.userError(w, r, badInput("The test mail could not be sent: "+err.Error()))
			return
		}
		s.audit(r, "notify.test", "mail", value)
		http.Redirect(w, r, "/admin?mail=sent#notifications", http.StatusSeeOther)
		return
	}
	if err := s.store.SetSetting(ctx, worker.SettingNotifyTo, value); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, "notify.update", "mail", value)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) auditLog(w http.ResponseWriter, r *http.Request) {
	entries, err := s.store.ListAudit(r.Context(), 500)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "audit", entries)
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
