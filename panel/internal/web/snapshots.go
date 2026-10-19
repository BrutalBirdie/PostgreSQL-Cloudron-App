package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"pgpanel/internal/schedule"
	"pgpanel/internal/store"
	"pgpanel/internal/worker"
)

// authorizeDatabase returns the database when the session may manage it. Unknown
// and foreign databases both return ErrNotFound.
func (s *Server) authorizeDatabase(r *http.Request, name string) (*store.Database, error) {
	db, err := s.store.GetDatabase(r.Context(), name)
	if err != nil {
		return nil, err
	}
	role, err := s.store.GetRole(r.Context(), db.Owner)
	if err != nil {
		return nil, err
	}
	if !canManage(r, role) {
		return nil, store.ErrNotFound
	}
	return db, nil
}

func (s *Server) authorizeSnapshot(r *http.Request) (*store.Snapshot, *store.Database, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return nil, nil, store.ErrNotFound
	}
	snap, err := s.store.GetSnapshot(r.Context(), id)
	if err != nil {
		return nil, nil, err
	}
	db, err := s.authorizeDatabase(r, snap.Database)
	if err != nil {
		return nil, nil, err
	}
	// a database name can be reused by another role after a drop
	if snap.OwnerRole != db.Owner {
		return nil, nil, store.ErrNotFound
	}
	return snap, db, nil
}

type cronPreset struct{ Cron, Label string }

var cronPresets = []cronPreset{{"", "Off"}, {"0 * * * *", "Every hour"}, {"0 */6 * * *", "Every 6 hours"}, {"0 3 * * *", "Daily 03:00 UTC"}, {"0 3 * * 0", "Sundays 03:00 UTC"}}

type databaseData struct {
	Database     store.Database
	Role         store.Role
	URL          string // connection URL with the user's own login, empty without one
	Snapshots    []store.Snapshot
	Jobs         []store.Job
	Active       *store.Job // queued or running job
	JobKey       string     // newest job and its status, live.js reloads the page parts when it changes
	MaxSnapshots int
	Schedule     *store.Schedule
	Presets      []cronPreset
	Preset       string // checked preset, "custom" for other schedules
	Stats        store.DatabaseStats
	Back, BackLabel string
}

func jobKey(jobs []store.Job) string {
	if len(jobs) == 0 {
		return "none"
	}
	return fmt.Sprintf("%d:%s", jobs[0].ID, jobs[0].Status)
}

func (s *Server) databasePage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db, err := s.authorizeDatabase(r, r.PathValue("name"))
	if err != nil {
		s.userError(w, r, err)
		return
	}
	role, err := s.store.GetRole(ctx, db.Owner)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	snaps, err := s.store.ListSnapshots(ctx, db.Name)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	jobs, err := s.store.ListJobs(ctx, db.Name, 5)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	sched, err := s.store.GetSchedule(ctx, db.Name)
	if errors.Is(err, store.ErrNotFound) || (err == nil && sched.OwnerRole != db.Owner) {
		sched, err = nil, nil
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	stats, err := s.store.DatabaseStats(ctx, db.Name)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	data := databaseData{Database: *db, Role: *role, Snapshots: snaps, Jobs: jobs, JobKey: jobKey(jobs), MaxSnapshots: s.cfg.MaxSnapshots,
		Schedule: sched, Presets: cronPresets, Preset: "custom", Stats: stats[db.Name], Back: "/", BackLabel: "My databases"}
	if len(jobs) > 0 && jobs[0].Active() {
		data.Active = &jobs[0]
	}
	current := ""
	if sched != nil {
		current = sched.Cron
	}
	for _, p := range cronPresets {
		if p.Cron == current {
			data.Preset = current
		}
	}
	if login, err := s.store.LoginOf(ctx, role.Name, sessionFrom(r).Username); err == nil && !login.Revoked {
		data.URL = s.connURL(login.LoginRole, db.Name)
	}
	if !owns(r, role) {
		data.Back, data.BackLabel = "/admin/databases", "Databases"
	}
	s.render(w, r, http.StatusOK, "database", data)
}

type jobEvent struct {
	Key      string `json:"key"`
	Active   bool   `json:"active"`
	Title    string `json:"title,omitempty"`
	Step     string `json:"step,omitempty"`
	Progress *int   `json:"progress"`
}

// databaseEvents streams the state of the newest job as server-sent events.
// It polls the jobs table, which the worker updates, so it works with any
// number of panel processes.
func (s *Server) databaseEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	db, err := s.authorizeDatabase(r, r.PathValue("name"))
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		http.Error(w, "not logged in", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	// https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffering
	h.Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	rc.SetWriteDeadline(time.Time{})

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var last string
	var lastWrite, lastCheck time.Time
	for {
		if time.Since(lastCheck) > 30*time.Second {
			ok, err := s.store.SessionValid(ctx, cookie.Value, idleTimeout, maxSession)
			if err != nil || !ok {
				return
			}
			lastCheck = time.Now()
		}
		jobs, err := s.store.ListJobs(ctx, db.Name, 1)
		if err != nil {
			if ctx.Err() == nil {
				s.log.Error("reading jobs for live updates", "database", db.Name, "err", err)
			}
			return
		}
		ev := jobEvent{Key: jobKey(jobs)}
		if len(jobs) > 0 && jobs[0].Active() {
			ev.Active, ev.Title, ev.Step, ev.Progress = true, jobTitle(jobs[0]), jobs[0].Step, jobs[0].Progress
		}
		b, _ := json.Marshal(ev)
		switch {
		case string(b) != last:
			fmt.Fprintf(w, "data: %s\n\n", b)
		case time.Since(lastWrite) > 15*time.Second:
			// keeps proxies from closing an idle stream
			fmt.Fprint(w, ": keepalive\n\n")
		default:
			b = nil
		}
		if b != nil {
			if err := rc.Flush(); err != nil {
				return
			}
			last, lastWrite = string(b), time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (s *Server) saveSchedule(w http.ResponseWriter, r *http.Request) {
	db, err := s.authorizeDatabase(r, r.PathValue("name"))
	if err != nil {
		s.userError(w, r, err)
		return
	}
	expr := strings.TrimSpace(r.PostForm.Get("cron"))
	if preset, ok := r.PostForm["preset"]; ok && preset[0] != "custom" {
		expr = preset[0]
	}
	if r.PostForm.Get("action") == "disable" || expr == "" {
		if err := s.store.DeleteSchedule(r.Context(), db.Name); err != nil {
			s.internalError(w, r, err)
			return
		}
		s.audit(r, "schedule.disable", db.Name, "")
		http.Redirect(w, r, "/databases/"+db.Name, http.StatusSeeOther)
		return
	}
	parsed, err := schedule.Parse(expr)
	if err != nil {
		s.userError(w, r, badInput(err.Error()+"."))
		return
	}
	err = s.store.SetSchedule(r.Context(), store.Schedule{
		Database:  db.Name,
		OwnerRole: db.Owner,
		Cron:      parsed.String(),
		NextRun:   parsed.Next(time.Now()),
		UpdatedBy: sessionFrom(r).Username,
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, "schedule.set", db.Name, "cron="+parsed.String())
	http.Redirect(w, r, "/databases/"+db.Name, http.StatusSeeOther)
}

func (s *Server) createSnapshot(w http.ResponseWriter, r *http.Request) {
	db, err := s.authorizeDatabase(r, r.PathValue("name"))
	if err != nil {
		s.userError(w, r, err)
		return
	}
	if err := s.store.EnqueueSnapshot(r.Context(), db.Name, sessionFrom(r).Username); err != nil {
		s.userError(w, r, err)
		return
	}
	s.audit(r, "snapshot.create", db.Name, "")
	http.Redirect(w, r, "/databases/"+db.Name, http.StatusSeeOther)
}

func (s *Server) restoreSnapshot(w http.ResponseWriter, r *http.Request) {
	snap, db, err := s.authorizeSnapshot(r)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	if r.PostForm.Get("confirm") != db.Name {
		s.userError(w, r, badInput("Type the database name to confirm the restore."))
		return
	}
	safety := r.PostForm.Get("safety_snapshot") == "on"
	if err := s.store.EnqueueRestore(r.Context(), db.Name, snap.ID, safety, sessionFrom(r).Username); err != nil {
		s.userError(w, r, err)
		return
	}
	s.audit(r, "snapshot.restore", db.Name, fmt.Sprintf("snapshot=%d safety_snapshot=%t", snap.ID, safety))
	http.Redirect(w, r, "/databases/"+db.Name, http.StatusSeeOther)
}

func (s *Server) deleteSnapshot(w http.ResponseWriter, r *http.Request) {
	snap, db, err := s.authorizeSnapshot(r)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	file, err := s.store.DeleteSnapshot(r.Context(), snap.ID)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	worker.RemoveFiles(s.cfg.SnapshotDir, []string{file}, s.log)
	s.audit(r, "snapshot.delete", db.Name, fmt.Sprintf("snapshot=%d", snap.ID))
	http.Redirect(w, r, safeNext(r.PostForm.Get("next"), "/databases/"+db.Name), http.StatusSeeOther)
}

func (s *Server) downloadSnapshot(w http.ResponseWriter, r *http.Request) {
	snap, db, err := s.authorizeSnapshot(r)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	path, err := worker.Resolve(s.cfg.SnapshotDir, snap.File)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	format := r.URL.Query().Get("format")
	if format != "sql" {
		format = "dump"
	}
	f, err := os.Open(path)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	defer f.Close()

	s.audit(r, "snapshot.download", db.Name, fmt.Sprintf("snapshot=%d format=%s", snap.ID, format))
	// large dumps take longer than the server's default write timeout
	http.NewResponseController(w).SetWriteDeadline(time.Time{})
	name := fmt.Sprintf("%s-%s.%s", db.Name, snap.CreatedAt.UTC().Format("20060102T150405Z"), format)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)

	if format == "dump" {
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, name, snap.CreatedAt, f)
		return
	}
	w.Header().Set("Content-Type", "application/sql; charset=utf-8")
	// converting the archive to SQL needs no database connection
	cmd := exec.CommandContext(r.Context(), filepath.Join(s.cfg.PGBinDir, "pg_restore"), "--no-owner", "--no-acl", "--file=-")
	cmd.Stdin = f
	cmd.Stdout = w
	if err := cmd.Run(); err != nil && r.Context().Err() == nil {
		s.log.Error("sql download", "snapshot", snap.ID, "err", err)
	}
}
