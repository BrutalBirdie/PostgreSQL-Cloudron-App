// Package worker runs snapshot and restore jobs. It runs as the postgres OS
// user and calls pg_dump and pg_restore as the database's owner role, so tenant
// controlled content is never processed with superuser rights.
package worker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"pgpanel/internal/names"
	"pgpanel/internal/schedule"
	"pgpanel/internal/store"
)

type Config struct {
	SnapshotDir  string
	SocketDir    string
	BinDir       string
	MaxSnapshots int
}

type Worker struct {
	cfg   Config
	store *store.Store
	log   *slog.Logger
}

func New(cfg Config, st *store.Store, log *slog.Logger) *Worker {
	return &Worker{cfg: cfg, store: st, log: log}
}

// Resolve maps a stored relative snapshot path to an absolute one inside dir.
func Resolve(dir, rel string) (string, error) {
	abs := filepath.Join(dir, rel)
	r, err := filepath.Rel(dir, abs)
	if err != nil || r == ".." || strings.HasPrefix(r, "../") || filepath.IsAbs(rel) {
		return "", fmt.Errorf("snapshot path %q escapes the snapshot directory", rel)
	}
	return abs, nil
}

func RemoveFiles(dir string, files []string, log *slog.Logger) {
	for _, f := range files {
		p, err := Resolve(dir, f)
		if err == nil {
			err = os.Remove(p)
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Error("removing snapshot file", "file", f, "err", err)
		}
	}
}

func (w *Worker) Run(ctx context.Context) error {
	if err := w.store.FailInterruptedJobs(ctx); err != nil {
		return err
	}
	w.removePartials()
	w.log.Info("worker started", "max_snapshots", w.cfg.MaxSnapshots)
	for {
		w.enqueueDue(ctx)
		job, err := w.store.ClaimJob(ctx)
		if err != nil && ctx.Err() == nil {
			w.log.Error("claiming job", "err", err)
		}
		if job == nil {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
			}
			continue
		}
		w.log.Info("job started", "id", job.ID, "kind", job.Kind, "database", job.Database)
		jobErr := w.run(ctx, job)
		if jobErr != nil {
			w.log.Error("job failed", "id", job.ID, "err", jobErr)
		} else {
			w.log.Info("job done", "id", job.ID)
		}
		if err := w.store.FinishJob(context.WithoutCancel(ctx), job.ID, jobErr); err != nil {
			w.log.Error("finishing job", "id", job.ID, "err", err)
		}
	}
}

func (w *Worker) run(ctx context.Context, job *store.Job) error {
	db, err := w.store.GetDatabase(ctx, job.Database)
	if err != nil {
		return fmt.Errorf("database %s: %w", job.Database, err)
	}
	if err := names.Validate(db.Name); err != nil {
		return err
	}
	if err := names.Validate(db.Owner); err != nil {
		return err
	}
	switch job.Kind {
	case "snapshot":
		kind := store.KindManual
		if job.Scheduled {
			kind = store.KindScheduled
		}
		id, err := w.snapshot(ctx, db, job.RequestedBy, kind, "")
		if err != nil {
			return err
		}
		w.prune(ctx, db.Name, kind, id)
		return nil
	case "restore":
		if job.SnapshotID == nil {
			return errors.New("restore job without snapshot")
		}
		return w.restore(ctx, db, *job.SnapshotID, job.RequestedBy)
	}
	return fmt.Errorf("unknown job kind %q", job.Kind)
}

func (w *Worker) snapshot(ctx context.Context, db *store.Database, by, kind, note string) (int64, error) {
	dir := filepath.Join(w.cfg.SnapshotDir, db.Name)
	if err := ensureSharedDir(dir); err != nil {
		return 0, err
	}
	suffix := make([]byte, 4)
	rand.Read(suffix)
	rel := filepath.Join(db.Name, time.Now().UTC().Format("20060102T150405Z")+"-"+hex.EncodeToString(suffix)+".dump")
	final := filepath.Join(w.cfg.SnapshotDir, rel)
	tmp := final + ".partial"
	defer os.Remove(tmp)

	if err := w.exec(ctx, "pg_dump", "--format=custom", "--no-owner", "--no-acl",
		"--host="+w.cfg.SocketDir, "--username="+db.Owner, "--dbname="+db.Name, "--file="+tmp); err != nil {
		return 0, err
	}
	if err := os.Chmod(tmp, 0o640); err != nil {
		return 0, err
	}
	info, err := os.Stat(tmp)
	if err != nil {
		return 0, err
	}
	if err := os.Rename(tmp, final); err != nil {
		return 0, err
	}
	id, err := w.store.AddSnapshot(ctx, store.Snapshot{Database: db.Name, OwnerRole: db.Owner, Kind: kind, File: rel, SizeBytes: info.Size(), Note: note, CreatedBy: by})
	if err != nil {
		os.Remove(final)
		return 0, err
	}
	return id, nil
}

// ensureSharedDir creates a snapshot directory the panel (group cloudron) can
// read and delete in. The group comes from the setgid parent, which new
// directories inherit. chmod is not used: the kernel clears setgid when the
// caller (postgres) is not in the directory's group. The worker runs with umask 007.
func ensureSharedDir(dir string) error {
	if err := os.MkdirAll(dir, 0o770); err != nil {
		return err
	}
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSetgid == 0 || info.Mode().Perm()&0o070 != 0o070 {
		return fmt.Errorf("%s has mode %v, it needs setgid and group rwx (restart the app to repair)", dir, info.Mode())
	}
	return nil
}

// removePartials deletes dumps left behind by a pg_dump that was interrupted by a restart.
func (w *Worker) removePartials() {
	partials, _ := filepath.Glob(filepath.Join(w.cfg.SnapshotDir, "*", "*.partial"))
	for _, p := range partials {
		if err := os.Remove(p); err != nil {
			w.log.Error("removing partial snapshot", "file", p, "err", err)
		}
	}
}

func (w *Worker) restore(ctx context.Context, db *store.Database, snapshotID int64, by string) error {
	snap, err := w.store.GetSnapshot(ctx, snapshotID)
	if err != nil {
		return err
	}
	// never restore another tenant's data, even if a database name was reused
	if snap.Database != db.Name || snap.OwnerRole != db.Owner {
		return errors.New("snapshot does not belong to this database")
	}
	file, err := Resolve(w.cfg.SnapshotDir, snap.File)
	if err != nil {
		return err
	}
	if err := w.exec(ctx, "pg_restore", "--list", file); err != nil {
		return fmt.Errorf("snapshot file is not readable: %w", err)
	}

	before, err := w.snapshot(ctx, db, by, store.KindPreRestore, fmt.Sprintf("taken before restoring snapshot #%d", snap.ID))
	if err != nil {
		return fmt.Errorf("safety snapshot before restore failed, database unchanged: %w", err)
	}
	if err := w.store.RecreateDatabase(ctx, db.Name, db.Owner); err != nil {
		return fmt.Errorf("recreating database: %w (snapshot #%d has the previous contents)", err, before)
	}
	if err := w.exec(ctx, "pg_restore", "--no-owner", "--no-acl", "--single-transaction", "--exit-on-error",
		"--host="+w.cfg.SocketDir, "--username="+db.Owner, "--dbname="+db.Name, file); err != nil {
		return fmt.Errorf("restore failed, the database is empty: %w (snapshot #%d has the previous contents)", err, before)
	}
	w.prune(ctx, db.Name, store.KindPreRestore, snap.ID, before)
	return nil
}

func (w *Worker) prune(ctx context.Context, database, kind string, protect ...int64) {
	files, err := w.store.PruneSnapshots(ctx, database, kind, w.cfg.MaxSnapshots, protect...)
	if err != nil {
		w.log.Error("pruning snapshots", "database", database, "err", err)
		return
	}
	RemoveFiles(w.cfg.SnapshotDir, files, w.log)
}

// enqueueDue turns due schedules into jobs and moves each schedule to its next run.
func (w *Worker) enqueueDue(ctx context.Context) {
	due, err := w.store.DueSchedules(ctx)
	if err != nil {
		if ctx.Err() == nil {
			w.log.Error("reading schedules", "err", err)
		}
		return
	}
	for _, sc := range due {
		db, err := w.store.GetDatabase(ctx, sc.Database)
		if errors.Is(err, store.ErrNotFound) || (err == nil && db.Owner != sc.OwnerRole) {
			w.log.Info("removing schedule of a deleted or reassigned database", "database", sc.Database)
			if err := w.store.DeleteSchedule(ctx, sc.Database); err != nil {
				w.log.Error("removing schedule", "database", sc.Database, "err", err)
			}
			continue
		}
		if err != nil {
			w.log.Error("reading database", "database", sc.Database, "err", err)
			continue
		}
		parsed, err := schedule.Parse(sc.Cron)
		if err != nil {
			w.log.Error("invalid stored schedule", "database", sc.Database, "cron", sc.Cron, "err", err)
			continue
		}
		// computed from now, so runs missed while the app was down collapse into one
		if err := w.store.SetNextRun(ctx, sc.Database, parsed.Next(time.Now())); err != nil {
			w.log.Error("updating schedule", "database", sc.Database, "err", err)
			continue
		}
		err = w.store.EnqueueScheduled(ctx, sc.Database)
		if errors.Is(err, store.ErrJobActive) {
			w.log.Info("scheduled snapshot skipped, a job is still running", "database", sc.Database)
		} else if err != nil {
			w.log.Error("queueing scheduled snapshot", "database", sc.Database, "err", err)
		}
	}
}

func (w *Worker) exec(ctx context.Context, tool string, args ...string) error {
	cmd := exec.CommandContext(ctx, filepath.Join(w.cfg.BinDir, tool), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if len(msg) > 500 {
			msg = msg[:500] + "..."
		}
		return fmt.Errorf("%s: %v: %s", tool, err, msg)
	}
	return nil
}
