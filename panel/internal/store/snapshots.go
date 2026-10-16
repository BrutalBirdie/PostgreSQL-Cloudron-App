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
	UploadID    *int64
	Strict      bool
	Safety      bool // take a safety snapshot before a restore or import
	Progress    *int // percent, nil when unknown
	Step        string
	StartedAt   *time.Time
	RequestedBy string
	Status      string
	Error       string
	CreatedAt   time.Time
	FinishedAt  *time.Time
	Scheduled   bool
}

func (j Job) Active() bool { return j.Status == "queued" || j.Status == "running" }

func (s *Store) EnqueueSnapshot(ctx context.Context, database, by string) error {
	return s.enqueue(ctx, "snapshot", database, nil, by, false, true)
}

func (s *Store) EnqueueRestore(ctx context.Context, database string, snapshotID int64, safetySnapshot bool, by string) error {
	return s.enqueue(ctx, "restore", database, &snapshotID, by, false, safetySnapshot)
}

func (s *Store) enqueue(ctx context.Context, kind, database string, snapshotID *int64, by string, scheduled, safetySnapshot bool) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO jobs (kind, database, snapshot_id, requested_by, scheduled, safety_snapshot) VALUES ($1, $2, $3, $4, $5, $6)`,
		kind, database, snapshotID, by, scheduled, safetySnapshot)
	return asJobActive(err)
}

// asJobActive maps the one-active-job-per-database index violation to ErrJobActive.
func asJobActive(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "jobs_one_active" {
		return ErrJobActive
	}
	return err
}

func (s *Store) ListJobs(ctx context.Context, database string, limit int) ([]Job, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, kind, database, snapshot_id, upload_id, strict, safety_snapshot, progress, progress_step, started_at, requested_by, status, error, created_at, finished_at, scheduled
FROM jobs WHERE database = $1 ORDER BY id DESC LIMIT $2`, database, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanJob)
}

func scanJob(r pgx.CollectableRow) (Job, error) {
	var j Job
	var progress *int16
	err := r.Scan(&j.ID, &j.Kind, &j.Database, &j.SnapshotID, &j.UploadID, &j.Strict, &j.Safety, &progress, &j.Step, &j.StartedAt, &j.RequestedBy, &j.Status, &j.Error, &j.CreatedAt, &j.FinishedAt, &j.Scheduled)
	if progress != nil {
		p := int(*progress)
		j.Progress = &p
	}
	return j, err
}

// ClaimJob marks the oldest queued job as running, nil when there is none.
func (s *Store) ClaimJob(ctx context.Context) (*Job, error) {
	rows, err := s.pool.Query(ctx, `
UPDATE jobs SET status = 'running', started_at = now()
WHERE id = (SELECT id FROM jobs WHERE status = 'queued' ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)
RETURNING id, kind, database, snapshot_id, upload_id, strict, safety_snapshot, progress, progress_step, started_at, requested_by, status, error, created_at, finished_at, scheduled`)
	if err != nil {
		return nil, err
	}
	j, err := pgx.CollectExactlyOneRow(rows, scanJob)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &j, err
}

// Warning marks a job that finished but has something to report.
type Warning struct{ Msg string }

func (w Warning) Error() string { return w.Msg }

// SetJobProgress stores the progress of a running job, pct < 0 means unknown.
func (s *Store) SetJobProgress(ctx context.Context, id int64, pct int, step string) error {
	var p *int
	if pct >= 0 {
		p = &pct
	}
	_, err := s.pool.Exec(ctx, `UPDATE jobs SET progress = $2, progress_step = $3 WHERE id = $1 AND status = 'running'`, id, p, step)
	return err
}

func (s *Store) FinishJob(ctx context.Context, id int64, jobErr error) error {
	status, msg := "done", ""
	var warn Warning
	if errors.As(jobErr, &warn) {
		msg = warn.Msg
	} else if jobErr != nil {
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

// Databases with this prefix are internal: staging databases a restore loads
// into and replaced databases waiting to be dropped. The panel never lists them.
const InternalPrefix = "pgpanel_"

func StagingName(jobID int64) string  { return fmt.Sprintf("%sstaging_%d", InternalPrefix, jobID) }
func replacedName(jobID int64) string { return fmt.Sprintf("%sreplaced_%d", InternalPrefix, jobID) }

// CreateStaging creates the empty database a restore loads into, locked down
// like any tenant database. The worker runs these as superuser and only
// executes fixed DDL, never anything from the tenant's data.
func (s *Store) CreateStaging(ctx context.Context, staging, owner string) error {
	for _, sql := range []string{
		fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, ident(staging)),
		fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, ident(staging), ident(owner)),
		fmt.Sprintf(`REVOKE ALL ON DATABASE %[1]s FROM PUBLIC; GRANT CONNECT, TEMPORARY ON DATABASE %[1]s TO %[2]s`, ident(staging), ident(owner)),
	} {
		if _, err := s.pool.Exec(ctx, sql); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) DropInternal(ctx context.Context, name string) error {
	_, err := s.pool.Exec(ctx, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, ident(name)))
	return err
}

// DropAllInternal removes staging and replaced databases left by an interrupted worker.
func (s *Store) DropAllInternal(ctx context.Context) error {
	rows, err := s.pool.Query(ctx, `SELECT datname FROM pg_database WHERE starts_with(datname, $1)`, InternalPrefix)
	if err != nil {
		return err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return err
	}
	for _, n := range names {
		if err := s.DropInternal(ctx, n); err != nil {
			return err
		}
	}
	return nil
}

// SwapStaging replaces database name with the loaded staging database. Both
// renames run in one transaction, so the name always points to a database.
func (s *Store) SwapStaging(ctx context.Context, name string, jobID int64) error {
	staging, replaced := StagingName(jobID), replacedName(jobID)
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	// a rename needs the database without sessions, stop clients from reconnecting first
	if _, err := conn.Exec(ctx, fmt.Sprintf(`ALTER DATABASE %s ALLOW_CONNECTIONS false`, ident(name))); err != nil {
		return err
	}
	reopen := func() {
		conn.Exec(context.WithoutCancel(ctx), fmt.Sprintf(`ALTER DATABASE %s ALLOW_CONNECTIONS true`, ident(name)))
	}
	for i := 0; ; i++ {
		var left int
		err := conn.QueryRow(ctx, `SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, name).Scan(&left)
		if err != nil {
			reopen()
			return err
		}
		if left == 0 {
			break
		}
		if i == 50 {
			reopen()
			return errors.New("clients did not disconnect from the database")
		}
		time.Sleep(200 * time.Millisecond)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		reopen()
		return err
	}
	_, err = tx.Exec(ctx, fmt.Sprintf(`ALTER DATABASE %s RENAME TO %s`, ident(name), ident(replaced)))
	if err == nil {
		_, err = tx.Exec(ctx, fmt.Sprintf(`ALTER DATABASE %s RENAME TO %s`, ident(staging), ident(name)))
	}
	if err == nil {
		err = tx.Commit(ctx)
	}
	if err != nil {
		tx.Rollback(context.WithoutCancel(ctx))
		reopen()
		return err
	}
	_, err = conn.Exec(ctx, fmt.Sprintf(`DROP DATABASE %s WITH (FORCE)`, ident(replaced)))
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
	return s.enqueue(ctx, "snapshot", database, nil, "schedule", true, true)
}

// AllSnapshotFiles maps every stored snapshot file to its id, for reconciling
// with the files on disk.
func (s *Store) AllSnapshotFiles(ctx context.Context) (map[string]int64, error) {
	rows, err := s.pool.Query(ctx, `SELECT file, id FROM snapshots`)
	if err != nil {
		return nil, err
	}
	files := map[string]int64{}
	for rows.Next() {
		var f string
		var id int64
		if err := rows.Scan(&f, &id); err != nil {
			return nil, err
		}
		files[f] = id
	}
	return files, rows.Err()
}
