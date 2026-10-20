package store

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pgpanel/internal/access"
	"pgpanel/internal/names"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrHasDatabases = errors.New("role still owns databases")
	ErrLimitReached = errors.New("database limit reached")
)

type Store struct {
	pool *pgxpool.Pool
}

func Open(ctx context.Context, connString string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// CreateSchema creates the panel's tables. One statement list runs as one
// implicit transaction, so the worker sees either no table or all of them.
func (s *Store) CreateSchema(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, schema)
	return err
}

// SchemaReady reports whether the panel has created its tables. It checks the
// catalog, so polling it does not log errors.
func (s *Store) SchemaReady(ctx context.Context) error {
	var ready bool
	if err := s.pool.QueryRow(ctx, `SELECT to_regclass('public.settings') IS NOT NULL`).Scan(&ready); err != nil {
		return err
	}
	if !ready {
		return errors.New("the panel has not created its tables yet")
	}
	return nil
}

func ident(name string) string { return pgx.Identifier{name}.Sanitize() }

func literal(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func hash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

type Session struct {
	Username    string
	DisplayName string
	IsAdmin     bool // stored value is the admin group membership at login
	CSRFToken   string
}

// CreateSession stores only a hash of the token, a database leak does not expose live sessions.
func (s *Store) CreateSession(ctx context.Context, token string, sess Session) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO sessions (id_hash, username, display_name, is_admin, csrf_token) VALUES ($1, $2, $3, $4, $5)`,
		hash(token), sess.Username, sess.DisplayName, sess.IsAdmin, sess.CSRFToken)
	return err
}

func (s *Store) GetSession(ctx context.Context, token string, idle, absolute time.Duration) (*Session, error) {
	var sess Session
	err := s.pool.QueryRow(ctx, `
UPDATE sessions SET last_seen_at = now()
WHERE id_hash = $1 AND last_seen_at > now() - $2 * interval '1 second' AND created_at > now() - $3 * interval '1 second'
RETURNING username, display_name, is_admin, csrf_token`,
		hash(token), int(idle.Seconds()), int(absolute.Seconds())).Scan(&sess.Username, &sess.DisplayName, &sess.IsAdmin, &sess.CSRFToken)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &sess, err
}

// SessionValid checks a session without counting it as activity, for long
// running requests.
func (s *Store) SessionValid(ctx context.Context, token string, idle, absolute time.Duration) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `
SELECT EXISTS (SELECT FROM sessions WHERE id_hash = $1 AND last_seen_at > now() - $2 * interval '1 second' AND created_at > now() - $3 * interval '1 second')`,
		hash(token), int(idle.Seconds()), int(absolute.Seconds())).Scan(&ok)
	return ok, err
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE id_hash = $1`, hash(token))
	return err
}

func (s *Store) PurgeExpired(ctx context.Context, idle, absolute time.Duration) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE last_seen_at < now() - $1 * interval '1 second' OR created_at < now() - $2 * interval '1 second'`,
		int(idle.Seconds()), int(absolute.Seconds()))
	if err != nil {
		return err
	}
	if _, err = s.pool.Exec(ctx, `DELETE FROM oidc_logins WHERE created_at < now() - interval '10 minutes'`); err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM jobs WHERE status IN ('done', 'failed') AND finished_at < now() - interval '30 days'`)
	return err
}

func (s *Store) SaveOIDCLogin(ctx context.Context, state, verifier, nonce string) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO oidc_logins (state_hash, verifier, nonce) VALUES ($1, $2, $3)`, hash(state), verifier, nonce)
	return err
}

// TakeOIDCLogin returns and deletes a pending login, so each state can be used once.
func (s *Store) TakeOIDCLogin(ctx context.Context, state string) (verifier, nonce string, err error) {
	err = s.pool.QueryRow(ctx, `DELETE FROM oidc_logins WHERE state_hash = $1 AND created_at > now() - interval '10 minutes' RETURNING verifier, nonce`,
		hash(state)).Scan(&verifier, &nonce)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return verifier, nonce, err
}

type AuditEntry struct {
	At     time.Time
	Actor  string
	Action string
	Target string
	Detail string
}

func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO audit_log (actor, action, target, detail) VALUES ($1, $2, $3, $4)`, e.Actor, e.Action, e.Target, e.Detail)
	return err
}

// AuditQuery filters the audit log. Category is the part of the action
// before the dot, Search matches any column as a substring.
type AuditQuery struct {
	Category, Search string
	Limit, Offset    int
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func (s *Store) ListAudit(ctx context.Context, q AuditQuery) ([]AuditEntry, error) {
	rows, err := s.pool.Query(ctx, `SELECT at, actor, action, target, detail FROM audit_log
		WHERE ($1 = '' OR split_part(action, '.', 1) = $1)
		  AND ($2 = '' OR concat_ws(' ', actor, action, target, detail) ILIKE '%' || $2 || '%')
		ORDER BY id DESC LIMIT $3 OFFSET $4`, q.Category, likeEscaper.Replace(q.Search), q.Limit, q.Offset)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditEntry, error) {
		var e AuditEntry
		err := r.Scan(&e.At, &e.Actor, &e.Action, &e.Target, &e.Detail)
		return e, err
	})
}

func (s *Store) AuditCategories(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT split_part(action, '.', 1) AS c FROM audit_log ORDER BY c`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

type Role struct {
	Name         string
	ConnLimit    int // applied to every login of the role
	Owners       []access.Principal
	MaxDatabases int // databases the owners may have in total via self-service, 0 disables it
	Databases    []string
}

func (r Role) OwnerUsers() []access.Principal  { return r.ownersOf(access.KindUser) }
func (r Role) OwnerGroups() []access.Principal { return r.ownersOf(access.KindGroup) }

func (r Role) ownersOf(kind string) []access.Principal {
	var out []access.Principal
	for _, p := range r.Owners {
		if p.Kind == kind {
			out = append(out, p)
		}
	}
	return out
}

type Database struct {
	Name  string
	Owner string // owner role
}

// tenantRoles is the only set of roles the panel ever touches. pgpanel is a
// member of tenants only to hold ADMIN on it.
const tenantRoles = `
SELECT r.rolname FROM pg_roles r
JOIN pg_auth_members m ON m.member = r.oid
JOIN pg_roles g ON g.oid = m.roleid AND g.rolname = 'tenants'
WHERE r.rolname <> 'pgpanel'`

func (s *Store) ListRoles(ctx context.Context) ([]Role, error) {
	owners, err := s.roleOwners(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
SELECT r.rolname, r.rolconnlimit, coalesce(o.max_databases, 0),
       coalesce(array_agg(d.datname ORDER BY d.datname) FILTER (WHERE d.datname IS NOT NULL), '{}')
FROM pg_roles r
LEFT JOIN role_settings o ON o.role_name = r.rolname
LEFT JOIN pg_database d ON d.datdba = r.oid AND NOT starts_with(d.datname, '`+InternalPrefix+`')
WHERE r.rolname IN (`+tenantRoles+`)
GROUP BY r.rolname, r.rolconnlimit, o.max_databases
ORDER BY r.rolname`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Role, error) {
		var role Role
		err := r.Scan(&role.Name, &role.ConnLimit, &role.MaxDatabases, &role.Databases)
		role.Owners = owners[role.Name]
		return role, err
	})
}

// RolesOwnedBy lists the roles the member owns by name or through a group.
func (s *Store) RolesOwnedBy(ctx context.Context, m access.Member) ([]Role, error) {
	all, err := s.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	var mine []Role
	for _, r := range all {
		if access.Owns(r.Owners, m) {
			mine = append(mine, r)
		}
	}
	return mine, nil
}

func (s *Store) GetRole(ctx context.Context, name string) (*Role, error) {
	all, err := s.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		if r.Name == name {
			return &r, nil
		}
	}
	return nil, ErrNotFound
}

func (s *Store) ListDatabases(ctx context.Context) ([]Database, error) {
	rows, err := s.pool.Query(ctx, `
SELECT d.datname, r.rolname FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba
WHERE NOT d.datistemplate AND NOT starts_with(d.datname, '`+InternalPrefix+`') AND r.rolname IN (`+tenantRoles+`)
ORDER BY d.datname`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Database, error) {
		var d Database
		err := r.Scan(&d.Name, &d.Owner)
		return d, err
	})
}

func (s *Store) GetDatabase(ctx context.Context, name string) (*Database, error) {
	all, err := s.ListDatabases(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range all {
		if d.Name == name {
			return &d, nil
		}
	}
	return nil, ErrNotFound
}

// CreateRole creates a shared role without password: people connect with
// their own login (SetLoginPassword), the worker through the peer map.
func (s *Store) CreateRole(ctx context.Context, name string, connLimit int, owners []access.Principal, maxDatabases int) error {
	if err := names.Validate(name); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT %d IN ROLE tenants PASSWORD NULL`,
		ident(name), connLimit))
	if err != nil {
		return err
	}
	if err := setOwners(ctx, tx, name, owners, maxDatabases); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func setOwners(ctx context.Context, tx pgx.Tx, role string, owners []access.Principal, maxDatabases int) error {
	if _, err := tx.Exec(ctx, `DELETE FROM role_access WHERE role_name = $1`, role); err != nil {
		return err
	}
	for _, p := range owners {
		if _, err := tx.Exec(ctx, `INSERT INTO role_access (role_name, kind, principal_id, display) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
			role, p.Kind, p.ID, p.Display); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `INSERT INTO role_settings (role_name, max_databases) VALUES ($1, $2)
ON CONFLICT (role_name) DO UPDATE SET max_databases = EXCLUDED.max_databases`, role, maxDatabases)
	return err
}

// UpdateRole replaces owners and limits. The connection limit applies to every
// login of the role; the worker revokes logins of users who lost access.
func (s *Store) UpdateRole(ctx context.Context, name string, owners []access.Principal, connLimit, maxDatabases int) error {
	if _, err := s.GetRole(ctx, name); err != nil {
		return err
	}
	logins, err := s.ListLogins(ctx, name)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, fmt.Sprintf(`ALTER ROLE %s CONNECTION LIMIT %d`, ident(name), connLimit)); err != nil {
		return err
	}
	for _, l := range logins {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`ALTER ROLE %s CONNECTION LIMIT %d`, ident(l.LoginRole), connLimit)); err != nil {
			return err
		}
	}
	if err := setOwners(ctx, tx, name, owners, maxDatabases); err != nil {
		return err
	}
	if err := requestAccessSync(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DropRole(ctx context.Context, name string) error {
	role, err := s.GetRole(ctx, name)
	if err != nil {
		return err
	}
	if len(role.Databases) > 0 {
		return fmt.Errorf("%w: %s", ErrHasDatabases, strings.Join(role.Databases, ", "))
	}
	logins, err := s.ListLogins(ctx, name)
	if err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// the role owns no database, so its logins cannot own objects anywhere
	for _, l := range logins {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`DROP ROLE IF EXISTS %s`, ident(l.LoginRole))); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(`DROP ROLE %s`, ident(name))); err != nil {
		return err
	}
	for _, sql := range []string{`DELETE FROM role_settings WHERE role_name = $1`, `DELETE FROM role_access WHERE role_name = $1`, `DELETE FROM role_logins WHERE role_name = $1`} {
		if _, err := tx.Exec(ctx, sql, name); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// asRole runs fn on a dedicated connection with SET ROLE, because database
// level DDL needs ownership and DROP DATABASE cannot run in a transaction.
func (s *Store) asRole(ctx context.Context, role string, fn func(c *pgx.Conn) error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, "SET ROLE "+ident(role)); err != nil {
		conn.Release()
		return err
	}
	fnErr := fn(conn.Conn())
	if _, err := conn.Exec(context.WithoutCancel(ctx), "RESET ROLE"); err != nil {
		// never hand a connection with a foreign role back to the pool
		conn.Conn().Close(context.WithoutCancel(ctx))
	}
	conn.Release()
	return fnErr
}

// CreateDatabase creates a database owned by a tenant role. With limit > 0 it
// fails when the role already owns limit databases.
func (s *Store) CreateDatabase(ctx context.Context, name, owner string, limit int) error {
	if err := names.Validate(name); err != nil {
		return err
	}
	if _, err := s.GetRole(ctx, owner); err != nil {
		return fmt.Errorf("owner role: %w", err)
	}
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	// CREATE DATABASE cannot run in a transaction, a session lock serializes the count and the create
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtext('pgpanel.create_database'))`); err != nil {
		return err
	}
	defer func() {
		if _, err := conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock(hashtext('pgpanel.create_database'))`); err != nil {
			conn.Conn().Close(context.WithoutCancel(ctx))
		}
	}()
	if limit > 0 {
		var owned int
		if err := conn.QueryRow(ctx, `SELECT count(*) FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba WHERE r.rolname = $1 AND NOT starts_with(d.datname, '`+InternalPrefix+`')`, owner).Scan(&owned); err != nil {
			return err
		}
		if owned >= limit {
			return fmt.Errorf("%w: role %s already owns %d of %d databases", ErrLimitReached, owner, owned, limit)
		}
	}
	// pgpanel has CREATEDB, the owner role has not; the grants need ownership
	if _, err := conn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s OWNER %s`, ident(name), ident(owner))); err != nil {
		return err
	}
	// same connection as the lock, a second one from the pool can deadlock under load
	_, err = conn.Exec(ctx, fmt.Sprintf(`SET ROLE %[2]s; REVOKE ALL ON DATABASE %[1]s FROM PUBLIC; GRANT CONNECT, TEMPORARY ON DATABASE %[1]s TO %[2]s; RESET ROLE`,
		ident(name), ident(owner)))
	if err != nil {
		// a database with default privileges would accept every tenant role
		bg := context.WithoutCancel(ctx)
		_, dropErr := conn.Exec(bg, "SET ROLE "+ident(owner))
		if dropErr == nil {
			_, dropErr = conn.Exec(bg, fmt.Sprintf(`DROP DATABASE %s WITH (FORCE)`, ident(name)))
		}
		if _, resetErr := conn.Exec(bg, "RESET ROLE"); resetErr != nil {
			conn.Conn().Close(bg)
		}
		return errors.Join(err, dropErr)
	}
	return nil
}

func (s *Store) DropDatabase(ctx context.Context, name string) error {
	db, err := s.GetDatabase(ctx, name)
	if err != nil {
		return err
	}
	return s.asRole(ctx, db.Owner, func(c *pgx.Conn) error {
		_, err := c.Exec(ctx, fmt.Sprintf(`DROP DATABASE %s WITH (FORCE)`, ident(name)))
		return err
	})
}

// HBAErrors lists parse errors of the hba file on disk, before it is loaded.
func (s *Store) HBAErrors(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT line_number || ': ' || error FROM pg_hba_file_rules WHERE error IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func (s *Store) ReloadConfig(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `SELECT pg_reload_conf()`)
	return err
}

type DatabaseStats struct {
	SizeBytes     int64
	Connections   int
	Snapshots     int
	SnapshotBytes int64
	LastSnapshot  *time.Time
}

// DatabaseStats returns sizes and snapshot totals of one database, or of all
// tenant databases when name is "". pg_database_size needs pg_read_all_stats.
func (s *Store) DatabaseStats(ctx context.Context, name string) (map[string]DatabaseStats, error) {
	rows, err := s.pool.Query(ctx, `
SELECT d.datname, pg_database_size(d.oid), coalesce(sd.numbackends, 0),
       count(sn.id), coalesce(sum(sn.size_bytes), 0)::bigint, max(sn.created_at)
FROM pg_database d
JOIN pg_roles r ON r.oid = d.datdba
LEFT JOIN pg_stat_database sd ON sd.datid = d.oid
LEFT JOIN snapshots sn ON sn.database = d.datname
WHERE NOT d.datistemplate AND NOT starts_with(d.datname, '`+InternalPrefix+`') AND r.rolname IN (`+tenantRoles+`)
  AND ($1 = '' OR d.datname = $1)
GROUP BY d.datname, d.oid, sd.numbackends`, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]DatabaseStats{}
	for rows.Next() {
		var n string
		var st DatabaseStats
		if err := rows.Scan(&n, &st.SizeBytes, &st.Connections, &st.Snapshots, &st.SnapshotBytes, &st.LastSnapshot); err != nil {
			return nil, err
		}
		out[n] = st
	}
	return out, rows.Err()
}
