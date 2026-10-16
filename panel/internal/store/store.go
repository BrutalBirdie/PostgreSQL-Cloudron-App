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

func (s *Store) Migrate(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS sessions (
    id_hash bytea PRIMARY KEY,
    username text NOT NULL,
    display_name text NOT NULL,
    is_admin boolean NOT NULL,
    csrf_token text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS oidc_logins (
    state_hash bytea PRIMARY KEY,
    verifier text NOT NULL,
    nonce text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS role_owners (
    role_name text PRIMARY KEY,
    owner text NOT NULL
);
ALTER TABLE role_owners ADD COLUMN IF NOT EXISTS max_databases integer NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS audit_log (
    id bigserial PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    actor text NOT NULL,
    action text NOT NULL,
    target text NOT NULL,
    detail text NOT NULL DEFAULT ''
);`)
	if err != nil {
		return err
	}
	if _, err = s.pool.Exec(ctx, migrateSnapshots); err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, migrateUploads)
	return err
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

func (s *Store) ListAudit(ctx context.Context, limit int) ([]AuditEntry, error) {
	rows, err := s.pool.Query(ctx, `SELECT at, actor, action, target, detail FROM audit_log ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (AuditEntry, error) {
		var e AuditEntry
		err := r.Scan(&e.At, &e.Actor, &e.Action, &e.Target, &e.Detail)
		return e, err
	})
}

type Role struct {
	Name         string
	ConnLimit    int
	Owner        string
	MaxDatabases int // databases the owner may have in total via self-service, 0 disables it
	Databases    []string
}

type Database struct {
	Name      string
	Owner     string // owner role
	OwnerUser string // Cloudron user of the owner role, only set by the web layer
}

// tenantRoles is the only set of roles the panel ever touches. pgpanel is a
// member of tenants only to hold ADMIN on it.
const tenantRoles = `
SELECT r.rolname FROM pg_roles r
JOIN pg_auth_members m ON m.member = r.oid
JOIN pg_roles g ON g.oid = m.roleid AND g.rolname = 'tenants'
WHERE r.rolname <> 'pgpanel'`

func (s *Store) ListRoles(ctx context.Context) ([]Role, error) {
	rows, err := s.pool.Query(ctx, `
SELECT r.rolname, r.rolconnlimit, coalesce(o.owner, ''), coalesce(o.max_databases, 0),
       coalesce(array_agg(d.datname ORDER BY d.datname) FILTER (WHERE d.datname IS NOT NULL), '{}')
FROM pg_roles r
LEFT JOIN role_owners o ON o.role_name = r.rolname
LEFT JOIN pg_database d ON d.datdba = r.oid AND NOT starts_with(d.datname, '`+InternalPrefix+`')
WHERE r.rolname IN (`+tenantRoles+`)
GROUP BY r.rolname, r.rolconnlimit, o.owner, o.max_databases
ORDER BY r.rolname`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Role, error) {
		var role Role
		err := r.Scan(&role.Name, &role.ConnLimit, &role.Owner, &role.MaxDatabases, &role.Databases)
		return role, err
	})
}

func (s *Store) RolesOwnedBy(ctx context.Context, user string) ([]Role, error) {
	all, err := s.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	var mine []Role
	for _, r := range all {
		if r.Owner == user {
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

func (s *Store) CreateRole(ctx context.Context, name, verifier string, connLimit int, owner string, maxDatabases int) error {
	if err := names.Validate(name); err != nil {
		return err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, fmt.Sprintf(`CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT %d IN ROLE tenants PASSWORD %s`,
		ident(name), connLimit, literal(verifier)))
	if err != nil {
		return err
	}
	if err := setOwner(ctx, tx, name, owner, maxDatabases); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) SetPassword(ctx context.Context, name, verifier string) error {
	if _, err := s.GetRole(ctx, name); err != nil {
		return err
	}
	_, err := s.pool.Exec(ctx, fmt.Sprintf(`ALTER ROLE %s PASSWORD %s`, ident(name), literal(verifier)))
	return err
}

func setOwner(ctx context.Context, tx pgx.Tx, role, owner string, maxDatabases int) error {
	var err error
	if owner == "" {
		_, err = tx.Exec(ctx, `DELETE FROM role_owners WHERE role_name = $1`, role)
	} else {
		_, err = tx.Exec(ctx, `INSERT INTO role_owners (role_name, owner, max_databases) VALUES ($1, $2, $3)
ON CONFLICT (role_name) DO UPDATE SET owner = EXCLUDED.owner, max_databases = EXCLUDED.max_databases`, role, owner, maxDatabases)
	}
	return err
}

func (s *Store) UpdateRole(ctx context.Context, name, owner string, connLimit, maxDatabases int) error {
	if _, err := s.GetRole(ctx, name); err != nil {
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
	if err := setOwner(ctx, tx, name, owner, maxDatabases); err != nil {
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
	if _, err := s.pool.Exec(ctx, fmt.Sprintf(`DROP ROLE %s`, ident(name))); err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `DELETE FROM role_owners WHERE role_name = $1`, name)
	return err
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
