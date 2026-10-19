package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

type Connection struct {
	PID          int
	Database     string
	Login        string
	ClientAddr   string // empty for socket connections
	Application  string
	State        string // active, idle, idle in transaction, ...
	BackendStart time.Time
	StateChange  *time.Time
	TLSVersion   string // empty without TLS
}

// Connections lists the client connections to tenant databases. Query text is
// left out, it can contain passwords or tenant data. Other roles' rows need
// pg_read_all_stats.
func (s *Store) Connections(ctx context.Context) ([]Connection, error) {
	rows, err := s.pool.Query(ctx, `
SELECT a.pid, a.datname, coalesce(a.usename, ''), coalesce(host(a.client_addr), ''), a.application_name,
       coalesce(a.state, ''), a.backend_start, a.state_change, coalesce(ssl.version, '')
FROM pg_stat_activity a
JOIN pg_database d ON d.datname = a.datname
JOIN pg_roles r ON r.oid = d.datdba
LEFT JOIN pg_stat_ssl ssl ON ssl.pid = a.pid AND ssl.ssl
WHERE a.backend_type = 'client backend' AND NOT starts_with(a.datname, '`+InternalPrefix+`') AND r.rolname IN (`+tenantRoles+`)
ORDER BY a.datname, a.backend_start`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Connection, error) {
		var c Connection
		err := r.Scan(&c.PID, &c.Database, &c.Login, &c.ClientAddr, &c.Application, &c.State, &c.BackendStart, &c.StateChange, &c.TLSVersion)
		return c, err
	})
}

type ServerSetting struct {
	Value          string // current_setting(), with unit
	PendingRestart bool
}

// ServerSettings returns the running values of the named parameters.
func (s *Store) ServerSettings(ctx context.Context, names []string) (map[string]ServerSetting, error) {
	rows, err := s.pool.Query(ctx, `SELECT name, current_setting(name), pending_restart FROM pg_settings WHERE name = ANY($1)`, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]ServerSetting{}
	for rows.Next() {
		var n string
		var st ServerSetting
		if err := rows.Scan(&n, &st.Value, &st.PendingRestart); err != nil {
			return nil, err
		}
		out[n] = st
	}
	return out, rows.Err()
}

// ConfigFileErrors lists problems PostgreSQL found in its configuration files
// on disk. pg_file_settings needs superuser, only the worker calls it.
func (s *Store) ConfigFileErrors(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT coalesce(sourcefile, '') || ':' || coalesce(sourceline::text, '') || ' ' || coalesce(name, '') || ': ' || error
FROM pg_file_settings WHERE error IS NOT NULL AND error <> 'setting could not be applied'`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
