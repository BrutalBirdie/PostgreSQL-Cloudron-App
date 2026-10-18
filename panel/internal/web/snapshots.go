package web

import (
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

type databaseData struct {
	Database     store.Database
	Snapshots    []store.Snapshot
	Jobs         []store.Job
	Busy         bool
	MaxSnapshots int
	Schedule     *store.Schedule
	Stats        store.DatabaseStats
}

func (s *Server) databasePage(w http.ResponseWriter, r *http.Request) {
	db, err := s.authorizeDatabase(r, r.PathValue("name"))
	if err != nil {
		s.userError(w, r, err)
		return
	}
	snaps, err := s.store.ListSnapshots(r.Context(), db.Name)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	jobs, err := s.store.ListJobs(r.Context(), db.Name, 5)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	sched, err := s.store.GetSchedule(r.Context(), db.Name)
	if errors.Is(err, store.ErrNotFound) || (err == nil && sched.OwnerRole != db.Owner) {
		sched, err = nil, nil
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	stats, err := s.store.DatabaseStats(r.Context(), db.Name)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	busy := len(jobs) > 0 && jobs[0].Active()
	s.render(w, r, http.StatusOK, "database", databaseData{Database: *db, Snapshots: snaps, Jobs: jobs, Busy: busy, MaxSnapshots: s.cfg.MaxSnapshots, Schedule: sched, Stats: stats[db.Name]})
}

func (s *Server) saveSchedule(w http.ResponseWriter, r *http.Request) {
	db, err := s.authorizeDatabase(r, r.PathValue("name"))
	if err != nil {
		s.userError(w, r, err)
		return
	}
	expr := strings.TrimSpace(r.PostForm.Get("cron"))
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

type restoreData struct {
	Snapshot store.Snapshot
	Database store.Database
}

func (s *Server) restorePage(w http.ResponseWriter, r *http.Request) {
	snap, db, err := s.authorizeSnapshot(r)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "restore", restoreData{Snapshot: *snap, Database: *db})
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
	http.Redirect(w, r, "/databases/"+db.Name, http.StatusSeeOther)
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
