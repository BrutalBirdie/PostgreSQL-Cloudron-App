package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

type TableSize struct {
	Name    string
	Bytes   int64
	EstRows float64 // pg_class.reltuples, -1 when the table was never analyzed
}

// TableSizes returns the heap size of every table in a database, keyed by
// oid. Only the worker calls it, as superuser: the session is pinned to
// pg_catalog so nothing the tenant created in the database can run.
func (s *Store) TableSizes(ctx context.Context, database string) (map[uint32]TableSize, error) {
	cfg := s.pool.Config().ConnConfig.Copy()
	cfg.Database = database
	cfg.RuntimeParams["search_path"] = "pg_catalog"
	cfg.RuntimeParams["application_name"] = "pgpanel-progress"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	rows, err := conn.Query(ctx, `
SELECT c.oid, pg_catalog.quote_ident(n.nspname) || '.' || pg_catalog.quote_ident(c.relname),
       pg_catalog.pg_relation_size(c.oid), c.reltuples
FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'm') AND n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg\_toast%'`)
	if err != nil {
		return nil, err
	}
	sizes := map[uint32]TableSize{}
	for rows.Next() {
		var oid uint32
		var t TableSize
		var est float32
		if err := rows.Scan(&oid, &t.Name, &t.Bytes, &est); err != nil {
			return nil, err
		}
		t.EstRows = float64(est)
		sizes[oid] = t
	}
	return sizes, rows.Err()
}

type CopyProgress struct {
	Relid  uint32
	Tuples int64
	Bytes  int64
}

// DumpCopyProgress returns what pg_dump is copying right now in a database.
// https://www.postgresql.org/docs/18/progress-reporting.html#COPY-PROGRESS-REPORTING
func (s *Store) DumpCopyProgress(ctx context.Context, database string) (*CopyProgress, error) {
	var p CopyProgress
	err := s.pool.QueryRow(ctx, `
SELECT c.relid, c.tuples_processed, c.bytes_processed
FROM pg_stat_progress_copy c JOIN pg_stat_activity a ON a.pid = c.pid
WHERE c.datname = $1 AND c.command = 'COPY TO' AND a.application_name = 'pg_dump'
LIMIT 1`, database).Scan(&p.Relid, &p.Tuples, &p.Bytes)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &p, err
}
