package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

const migrateUploads = `
CREATE TABLE IF NOT EXISTS uploads (
    id bigserial PRIMARY KEY,
    role_name text NOT NULL,
    file_name text NOT NULL,
    size_bytes bigint NOT NULL,
    uploaded_by text NOT NULL,
    keep boolean NOT NULL DEFAULT false,
    first_seen timestamptz NOT NULL DEFAULT now(),
    UNIQUE (role_name, file_name)
);
ALTER TABLE uploads ADD COLUMN IF NOT EXISTS sha256 text;
ALTER TABLE uploads ADD COLUMN IF NOT EXISTS verified_by text NOT NULL DEFAULT '';
ALTER TABLE uploads ADD COLUMN IF NOT EXISTS mtime timestamptz;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS upload_id bigint;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS strict boolean NOT NULL DEFAULT true;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS progress smallint;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS progress_step text NOT NULL DEFAULT '';
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS started_at timestamptz;
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS safety_snapshot boolean NOT NULL DEFAULT true;
ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_kind_check CHECK (kind IN ('snapshot', 'restore', 'import'));`

type Upload struct {
	ID         int64
	RoleName   string
	FileName   string
	SizeBytes  int64
	UploadedBy string
	Keep       bool
	FirstSeen  time.Time
	SHA256     string // empty until calculated
	VerifiedBy string // "browser" or "user" when a checksum computed elsewhere matched
}

const uploadColumns = `id, role_name, file_name, size_bytes, uploaded_by, keep, first_seen, coalesce(sha256, ''), verified_by`

func scanUpload(r pgx.CollectableRow) (Upload, error) {
	var u Upload
	err := r.Scan(&u.ID, &u.RoleName, &u.FileName, &u.SizeBytes, &u.UploadedBy, &u.Keep, &u.FirstSeen, &u.SHA256, &u.VerifiedBy)
	return u, err
}

// FileState is what the scanner sees on disk. A change of size or mtime
// invalidates the stored checksum.
type FileState struct {
	Size  int64
	MTime time.Time
}

// SyncUploads makes the uploads table match the files found in a role's
// directory. by is recorded for files that were not known yet.
func (s *Store) SyncUploads(ctx context.Context, role string, files map[string]FileState, by string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	names := make([]string, 0, len(files))
	for name, st := range files {
		names = append(names, name)
		if _, err := tx.Exec(ctx, `
INSERT INTO uploads (role_name, file_name, size_bytes, mtime, uploaded_by) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (role_name, file_name) DO UPDATE SET
    sha256 = CASE WHEN uploads.size_bytes = EXCLUDED.size_bytes AND uploads.mtime = EXCLUDED.mtime THEN uploads.sha256 END,
    verified_by = CASE WHEN uploads.size_bytes = EXCLUDED.size_bytes AND uploads.mtime = EXCLUDED.mtime THEN uploads.verified_by ELSE '' END,
    size_bytes = EXCLUDED.size_bytes,
    mtime = EXCLUDED.mtime`, role, name, st.Size, st.MTime, by); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM uploads WHERE role_name = $1 AND NOT (file_name = ANY($2))`, role, names); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) AddUpload(ctx context.Context, role, file string, st FileState, by, sha256, verifiedBy string) error {
	_, err := s.pool.Exec(ctx, `
INSERT INTO uploads (role_name, file_name, size_bytes, mtime, uploaded_by, sha256, verified_by) VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (role_name, file_name) DO UPDATE SET size_bytes = EXCLUDED.size_bytes, mtime = EXCLUDED.mtime, uploaded_by = EXCLUDED.uploaded_by,
    sha256 = EXCLUDED.sha256, verified_by = EXCLUDED.verified_by, first_seen = now()`, role, file, st.Size, st.MTime, by, sha256, verifiedBy)
	return err
}

// PendingHashes lists uploads whose checksum still has to be calculated.
func (s *Store) PendingHashes(ctx context.Context) ([]Upload, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+uploadColumns+` FROM uploads WHERE sha256 IS NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanUpload)
}

// SetUploadHash stores a checksum unless the file changed while it was hashed.
func (s *Store) SetUploadHash(ctx context.Context, id int64, st FileState, sha256 string) error {
	_, err := s.pool.Exec(ctx, `UPDATE uploads SET sha256 = $4 WHERE id = $1 AND size_bytes = $2 AND mtime = $3`, id, st.Size, st.MTime, sha256)
	return err
}

func (s *Store) SetUploadVerified(ctx context.Context, id int64, by string) error {
	_, err := s.pool.Exec(ctx, `UPDATE uploads SET verified_by = $2 WHERE id = $1`, id, by)
	return err
}

func (s *Store) ListUploads(ctx context.Context, role string) ([]Upload, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+uploadColumns+` FROM uploads WHERE role_name = $1 ORDER BY first_seen DESC, id DESC`, role)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanUpload)
}

func (s *Store) GetUpload(ctx context.Context, id int64) (*Upload, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+uploadColumns+` FROM uploads WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	u, err := pgx.CollectExactlyOneRow(rows, scanUpload)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &u, err
}

func (s *Store) SetUploadKeep(ctx context.Context, id int64, keep bool) error {
	_, err := s.pool.Exec(ctx, `UPDATE uploads SET keep = $2 WHERE id = $1`, id, keep)
	return err
}

func (s *Store) DeleteUpload(ctx context.Context, id int64) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM uploads WHERE id = $1`, id)
	return err
}

func (s *Store) DeleteUploadsOf(ctx context.Context, role string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM uploads WHERE role_name = $1`, role)
	return err
}

// ExpiredUploads lists uploads older than retention that are not kept.
func (s *Store) ExpiredUploads(ctx context.Context, retention time.Duration) ([]Upload, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+uploadColumns+` FROM uploads WHERE NOT keep AND first_seen < now() - $1 * interval '1 second'`, int64(retention.Seconds()))
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanUpload)
}

// UploadInUse reports whether a queued or running import uses the upload.
func (s *Store) UploadInUse(ctx context.Context, id int64) (bool, error) {
	var used bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM jobs WHERE upload_id = $1 AND status IN ('queued', 'running'))`, id).Scan(&used)
	return used, err
}

// EnqueueImport queues an import. strict imports run in one transaction and stop
// at the first error, otherwise pg_restore skips failing statements.
func (s *Store) EnqueueImport(ctx context.Context, database string, uploadID int64, strict, safetySnapshot bool, by string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO jobs (kind, database, upload_id, strict, safety_snapshot, requested_by) VALUES ('import', $1, $2, $3, $4, $5)`,
		database, uploadID, strict, safetySnapshot, by)
	return asJobActive(err)
}
