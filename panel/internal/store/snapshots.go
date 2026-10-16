package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrJobActive = errors.New("another snapshot or restore of this database is still running")

const migrateSnapshots = `
CREATE TABLE IF NOT EXISTS snapshots (
    id bigserial PRIMARY KEY,
    database text NOT NULL,
    owner_role text NOT NULL,
    file text NOT NULL,
    size_bytes bigint NOT NULL,
    note text NOT NULL DEFAULT '',
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS jobs (
    id bigserial PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('snapshot', 'restore')),
    database text NOT NULL,
    snapshot_id bigint,
    requested_by text NOT NULL,
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS jobs_one_active ON jobs (database) WHERE status IN ('queued', 'running');
ALTER TABLE snapshots ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'manual';
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS scheduled boolean NOT NULL DEFAULT false;
CREATE TABLE IF NOT EXISTS schedules (
    database text PRIMARY KEY,
    owner_role text NOT NULL,
    cron text NOT NULL,
    next_run timestamptz NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);`

// Snapshot kinds, each kind is rotated separately so frequent scheduled
// snapshots never push out a manual one.
const (
	KindManual     = "manual"
	KindScheduled  = "scheduled"
	KindPreRestore = "pre_restore"
)

type Snapshot struct {
	ID        int64
	Database  string
	OwnerRole string
	Kind      string
	File      string // relative to the snapshot directory
	SizeBytes int64
	Note      string
	CreatedBy string
	CreatedAt time.Time
}

type Job struct {
	ID          int64
	Kind        string
	Database    string
	SnapshotID  *int64
	RequestedBy string
	Status      string
	Error       string
	CreatedAt   time.Time
	FinishedAt  *time.Time
	Scheduled   bool
}

func (j Job) Active() bool { return j.Status == "queued" || j.Status == "running" }

func (s *Store) EnqueueJob(ctx context.Context, kind, database string, snapshotID *int64, by string) error {
	return s.enqueue(ctx, kind, database, snapshotID, by, false)
}

func (s *Store) enqueue(ctx context.Context, kind, database string, snapshotID *int64, by string, scheduled bool) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO jobs (kind, database, snapshot_id, requested_by, scheduled) VALUES ($1, $2, $3, $4, $5)`, kind, database, snapshotID, by, scheduled)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrJobActive
	}
	return err
}

func (s *Store) ListJobs(ctx context.Context, database string, limit int) ([]Job, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, kind, database, snapshot_id, requested_by, status, error, created_at, finished_at, scheduled
FROM jobs WHERE database = $1 ORDER BY id DESC LIMIT $2`, database, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanJob)
}

func scanJob(r pgx.CollectableRow) (Job, error) {
	var j Job
	err := r.Scan(&j.ID, &j.Kind, &j.Database, &j.SnapshotID, &j.RequestedBy, &j.Status, &j.Error, &j.CreatedAt, &j.FinishedAt, &j.Scheduled)
	return j, err
}

// ClaimJob marks the oldest queued job as running, nil when there is none.
func (s *Store) ClaimJob(ctx context.Context) (*Job, error) {
	rows, err := s.pool.Query(ctx, `
UPDATE jobs SET status = 'running'
WHERE id = (SELECT id FROM jobs WHERE status = 'queued' ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
RETURNING id, kind, database, snapshot_id, requested_by, status, error, created_at, finished_at, scheduled`)
	if err != nil {
		return nil, err
	}
	j, err := pgx.CollectExactlyOneRow(rows, scanJob)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &j, err
}

func (s *Store) FinishJob(ctx context.Context, id int64, jobErr error) error {
	status, msg := "done", ""
	if jobErr != nil {
		status, msg = "failed", jobErr.Error()
	}
	_, err := s.pool.Exec(ctx, `UPDATE jobs SET status = $2, error = $3, finished_at = now() WHERE id = $1`, id, status, msg)
	return err
}

// FailInterruptedJobs is called by the worker on start, a running job cannot survive a restart.
func (s *Store) FailInterruptedJobs(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `UPDATE jobs SET status = 'failed', error = 'interrupted by an app restart', finished_at = now() WHERE status = 'running'`)
	return err
}

func (s *Store) AddSnapshot(ctx context.Context, snap Snapshot) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `INSERT INTO snapshots (database, owner_role, kind, file, size_bytes, note, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		snap.Database, snap.OwnerRole, snap.Kind, snap.File, snap.SizeBytes, snap.Note, snap.CreatedBy).Scan(&id)
	return id, err
}

const snapshotColumns = `id, database, owner_role, kind, file, size_bytes, note, created_by, created_at`

func scanSnapshot(r pgx.CollectableRow) (Snapshot, error) {
	var sn Snapshot
	err := r.Scan(&sn.ID, &sn.Database, &sn.OwnerRole, &sn.Kind, &sn.File, &sn.SizeBytes, &sn.Note, &sn.CreatedBy, &sn.CreatedAt)
	return sn, err
}

func (s *Store) ListSnapshots(ctx context.Context, database string) ([]Snapshot, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+snapshotColumns+` FROM snapshots WHERE database = $1 ORDER BY id DESC`, database)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanSnapshot)
}

func (s *Store) GetSnapshot(ctx context.Context, id int64) (*Snapshot, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+snapshotColumns+` FROM snapshots WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	sn, err := pgx.CollectExactlyOneRow(rows, scanSnapshot)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &sn, err
}

// DeleteSnapshot removes the row and returns the file the caller has to delete.
func (s *Store) DeleteSnapshot(ctx context.Context, id int64) (string, error) {
	var file string
	err := s.pool.QueryRow(ctx, `DELETE FROM snapshots WHERE id = $1 RETURNING file`, id).Scan(&file)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return file, err
}

// DeleteSnapshotsOf removes all snapshot rows of a database, a new database with
// the same name must never see them.
func (s *Store) DeleteSnapshotsOf(ctx context.Context, database string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `DELETE FROM snapshots WHERE database = $1 RETURNING file`, database)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// PruneSnapshots keeps the newest keep snapshots of one kind of a database plus
// the protected ids and returns the files of the deleted rows.
func (s *Store) PruneSnapshots(ctx context.Context, database, kind string, keep int, protect ...int64) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
DELETE FROM snapshots WHERE database = $1 AND kind = $4 AND NOT (id = ANY($3)) AND id NOT IN (
    SELECT id FROM snapshots WHERE database = $1 AND kind = $4 ORDER BY id DESC LIMIT $2
) RETURNING file`, database, keep, protect, kind)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// RecreateDatabase is used by the worker before a restore. It runs as superuser
// and only executes fixed DDL, never anything from the tenant's data.
func (s *Store) RecreateDatabase(ctx context.Context, name, owner string) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	steps := []string{
		fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, ident(name)),
		fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, ident(name), ident(owner)),
		fmt.Sprintf(`REVOKE ALL ON DATABASE %[1]s FROM PUBLIC; GRANT CONNECT, TEMPORARY ON DATABASE %[1]s TO %[2]s`, ident(name), ident(owner)),
	}
	for _, sql := range steps {
		if _, err := conn.Exec(ctx, sql); err != nil {
			return err
		}
	}
	return nil
}

// CheckSnapshotTables reports whether the panel has migrated the snapshot
// tables. It checks the catalog, so polling it does not log errors.
func (s *Store) CheckSnapshotTables(ctx context.Context) error {
	var ready bool
	err := s.pool.QueryRow(ctx, `
SELECT to_regclass('public.schedules') IS NOT NULL
   AND EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'snapshots' AND column_name = 'kind')
   AND EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'jobs' AND column_name = 'scheduled')`).Scan(&ready)
	if err == nil && !ready {
		err = errors.New("snapshot tables are not migrated yet")
	}
	return err
}

type Schedule struct {
	Database  string
	OwnerRole string
	Cron      string
	NextRun   time.Time
	UpdatedBy string
}

func (s *Store) GetSchedule(ctx context.Context, database string) (*Schedule, error) {
	var sc Schedule
	err := s.pool.QueryRow(ctx, `SELECT database, owner_role, cron, next_run, updated_by FROM schedules WHERE database = $1`, database).
		Scan(&sc.Database, &sc.OwnerRole, &sc.Cron, &sc.NextRun, &sc.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &sc, err
}

func (s *Store) SetSchedule(ctx context.Context, sc Schedule) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO schedules (database, owner_role, cron, next_run, updated_by) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (database) DO UPDATE SET owner_role = EXCLUDED.owner_role, cron = EXCLUDED.cron, next_run = EXCLUDED.next_run,
    updated_by = EXCLUDED.updated_by, updated_at = now()`, sc.Database, sc.OwnerRole, sc.Cron, sc.NextRun, sc.UpdatedBy)
	return err
}

func (s *Store) DeleteSchedule(ctx context.Context, database string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM schedules WHERE database = $1`, database)
	return err
}

func (s *Store) DueSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.pool.Query(ctx, `SELECT database, owner_role, cron, next_run, updated_by FROM schedules WHERE next_run <= now() ORDER BY next_run`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Schedule, error) {
		var sc Schedule
		err := r.Scan(&sc.Database, &sc.OwnerRole, &sc.Cron, &sc.NextRun, &sc.UpdatedBy)
		return sc, err
	})
}

func (s *Store) SetNextRun(ctx context.Context, database string, next time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE schedules SET next_run = $2 WHERE database = $1`, database, next)
	return err
}

// EnqueueScheduled adds a scheduled snapshot job. A run is skipped, not queued
// twice, when a job for the database is still active.
func (s *Store) EnqueueScheduled(ctx context.Context, database string) error {
	return s.enqueue(ctx, "snapshot", database, nil, "schedule", true)
}
