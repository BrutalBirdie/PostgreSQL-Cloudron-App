package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"pgpanel/internal/access"
)

// Login authentication methods, see role_logins.auth.
const (
	AuthPassword    = "password"
	AuthAppPassword = "apppw"
)

type Login struct {
	LoginRole string
	RoleName  string
	Username  string
	Auth      string // AuthPassword or AuthAppPassword
	Revoked   bool
	CreatedAt time.Time
	RotatedAt time.Time
}

var plainUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

// LoginName is the PostgreSQL login of a user for a shared role, e.g.
// "boidscan.james". Shared role names never contain a dot, so login names
// cannot collide with them.
func LoginName(role, username string) string {
	name := role + "." + username
	if plainUsername.MatchString(username) && len(name) <= 63 {
		return name
	}
	sum := sha256.Sum256([]byte(username))
	return role[:min(len(role), 54)] + "." + hex.EncodeToString(sum[:4])
}

func (s *Store) LoginOf(ctx context.Context, role, username string) (*Login, error) {
	rows, err := s.pool.Query(ctx, `SELECT login_role, role_name, username, auth, revoked, created_at, rotated_at FROM role_logins WHERE role_name = $1 AND username = $2`, role, username)
	if err != nil {
		return nil, err
	}
	l, err := pgx.CollectExactlyOneRow(rows, scanLogin)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &l, err
}

func scanLogin(r pgx.CollectableRow) (Login, error) {
	var l Login
	err := r.Scan(&l.LoginRole, &l.RoleName, &l.Username, &l.Auth, &l.Revoked, &l.CreatedAt, &l.RotatedAt)
	return l, err
}

// ListLogins returns the logins of one role, or of all roles when role is "".
func (s *Store) ListLogins(ctx context.Context, role string) ([]Login, error) {
	rows, err := s.pool.Query(ctx, `SELECT login_role, role_name, username, auth, revoked, created_at, rotated_at FROM role_logins
WHERE $1 = '' OR role_name = $1 ORDER BY role_name, username`, role)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanLogin)
}

// SetLoginPassword creates the user's login for a role or gives it a new
// password. The login is a member of the shared role and switches to it on
// connect (SET role), so everything it creates belongs to the shared role.
// A login that used app passwords goes back to its SCRAM password.
func (s *Store) SetLoginPassword(ctx context.Context, role, username, verifier string, connLimit int) (string, error) {
	return s.setLoginAuth(ctx, role, username, AuthPassword, verifier, connLimit)
}

// UseAppPassword makes the user's login for a role authenticate with Cloudron
// app passwords only. Its SCRAM password is removed.
func (s *Store) UseAppPassword(ctx context.Context, role, username string, connLimit int) (string, error) {
	return s.setLoginAuth(ctx, role, username, AuthAppPassword, "", connLimit)
}

func (s *Store) setLoginAuth(ctx context.Context, role, username, auth, verifier string, connLimit int) (string, error) {
	login := LoginName(role, username)
	existing, err := s.LoginOf(ctx, role, username)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return "", err
	}
	if existing != nil && existing.Revoked {
		return "", errors.New("this login is being removed, try again in a minute")
	}
	password := "NULL"
	if auth == AuthPassword {
		password = literal(verifier)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	if existing != nil {
		login = existing.LoginRole
		if _, err := tx.Exec(ctx, fmt.Sprintf(`ALTER ROLE %s PASSWORD %s`, ident(login), password)); err != nil {
			return "", err
		}
		if _, err := tx.Exec(ctx, `UPDATE role_logins SET auth = $2, rotated_at = now() WHERE login_role = $1`, login, auth); err != nil {
			return "", err
		}
	} else {
		for _, sql := range []string{
			fmt.Sprintf(`CREATE ROLE %s LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT %d IN ROLE %s PASSWORD %s`,
				ident(login), connLimit, ident(role), password),
			fmt.Sprintf(`ALTER ROLE %s SET role = %s`, ident(login), literal(role)),
		} {
			if _, err := tx.Exec(ctx, sql); err != nil {
				return "", err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO role_logins (login_role, role_name, username, auth) VALUES ($1, $2, $3, $4)`, login, role, username, auth); err != nil {
			return "", err
		}
	}
	// pg_hba.conf sends members of apppw to PAM, everyone else to SCRAM
	grant := ""
	switch {
	case auth == AuthAppPassword:
		grant = fmt.Sprintf(`GRANT apppw TO %s`, ident(login))
	case existing != nil && existing.Auth == AuthAppPassword:
		grant = fmt.Sprintf(`REVOKE apppw FROM %s`, ident(login))
	}
	if grant != "" {
		if _, err := tx.Exec(ctx, grant); err != nil {
			return "", err
		}
	}
	return login, tx.Commit(ctx)
}

// AppPasswordLogins maps every login that uses app passwords to its Cloudron username.
func (s *Store) AppPasswordLogins(ctx context.Context) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT login_role, username FROM role_logins WHERE auth = 'apppw' AND NOT revoked`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var login, username string
		if err := rows.Scan(&login, &username); err != nil {
			return nil, err
		}
		out[login] = username
	}
	return out, rows.Err()
}

// RevokeLogin stops new connections at once; the worker terminates sessions,
// moves owned objects to the shared role and drops the login.
func (s *Store) RevokeLogin(ctx context.Context, login string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, fmt.Sprintf(`ALTER ROLE %s NOLOGIN`, ident(login))); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE role_logins SET revoked = true WHERE login_role = $1`, login); err != nil {
		return err
	}
	if err := requestAccessSync(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) DeleteLoginRow(ctx context.Context, login string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM role_logins WHERE login_role = $1`, login)
	return err
}

func requestAccessSync(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('access_sync_requested', now()::text)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`)
	return err
}

// RequestAccessSync asks the worker to check all logins now, for example
// after owners changed.
func (s *Store) RequestAccessSync(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO settings (key, value) VALUES ('access_sync_requested', now()::text)
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`)
	return err
}

// Setting returns a stored setting, "" when it is not set.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, key).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return v, err
}

// SetSetting stores a setting, an empty value removes it.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	if value == "" {
		_, err := s.pool.Exec(ctx, `DELETE FROM settings WHERE key = $1`, key)
		return err
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`, key, value)
	return err
}

// TakeAccessSyncRequest reports and clears a pending request.
func (s *Store) TakeAccessSyncRequest(ctx context.Context) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM settings WHERE key = 'access_sync_requested'`)
	return tag.RowsAffected() > 0, err
}

func (s *Store) roleOwners(ctx context.Context) (map[string][]access.Principal, error) {
	rows, err := s.pool.Query(ctx, `SELECT role_name, kind, principal_id, display FROM role_access ORDER BY kind DESC, display, principal_id`)
	if err != nil {
		return nil, err
	}
	owners := map[string][]access.Principal{}
	for rows.Next() {
		var role string
		var p access.Principal
		if err := rows.Scan(&role, &p.Kind, &p.ID, &p.Display); err != nil {
			return nil, err
		}
		owners[role] = append(owners[role], p)
	}
	return owners, rows.Err()
}

// RemoveLogin fully removes a login (worker, superuser): no new connections,
// sessions ended, objects it owns handed to the shared role, then dropped.
func (s *Store) RemoveLogin(ctx context.Context, login, role string) error {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_roles WHERE rolname = $1)`, login).Scan(&exists); err != nil {
		return err
	}
	if exists {
		for _, sql := range []string{
			fmt.Sprintf(`ALTER ROLE %s NOLOGIN`, ident(login)),
			fmt.Sprintf(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = %s`, literal(login)),
		} {
			if _, err := s.pool.Exec(ctx, sql); err != nil {
				return err
			}
		}
		rows, err := s.pool.Query(ctx, `SELECT d.datname FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba WHERE r.rolname = $1 AND d.datallowconn`, role)
		if err != nil {
			return err
		}
		dbs, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		for _, db := range dbs {
			if err := s.inDatabase(ctx, db, fmt.Sprintf(`REASSIGN OWNED BY %[1]s TO %[2]s; DROP OWNED BY %[1]s`, ident(login), ident(role))); err != nil {
				return fmt.Errorf("database %s: %w", db, err)
			}
		}
		if _, err := s.pool.Exec(ctx, fmt.Sprintf(`DROP ROLE %s`, ident(login))); err != nil {
			return err
		}
	}
	return s.DeleteLoginRow(ctx, login)
}

// inDatabase runs fixed SQL in another database as superuser, pinned to
// pg_catalog so nothing the tenant created there can run.
func (s *Store) inDatabase(ctx context.Context, database, sql string) error {
	cfg := s.pool.Config().ConnConfig.Copy()
	cfg.Database = database
	cfg.RuntimeParams["search_path"] = "pg_catalog"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	_, err = conn.Exec(ctx, sql)
	return err
}
