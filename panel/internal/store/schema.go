package store

const schema = `
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
CREATE TABLE IF NOT EXISTS audit_log (
    id bigserial PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    actor text NOT NULL,
    action text NOT NULL,
    target text NOT NULL,
    detail text NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS role_settings (
    role_name text PRIMARY KEY,
    max_databases integer NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS role_access (
    role_name text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('user', 'group')),
    principal_id text NOT NULL,
    display text NOT NULL DEFAULT '',
    PRIMARY KEY (role_name, kind, principal_id)
);
CREATE TABLE IF NOT EXISTS role_logins (
    login_role text PRIMARY KEY,
    role_name text NOT NULL,
    username text NOT NULL,
    revoked boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    rotated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (role_name, username)
);
CREATE TABLE IF NOT EXISTS snapshots (
    id bigserial PRIMARY KEY,
    database text NOT NULL,
    owner_role text NOT NULL,
    kind text NOT NULL DEFAULT 'manual',
    file text NOT NULL,
    size_bytes bigint NOT NULL,
    note text NOT NULL DEFAULT '',
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS jobs (
    id bigserial PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('snapshot', 'restore', 'import')),
    database text NOT NULL,
    snapshot_id bigint,
    upload_id bigint,
    scheduled boolean NOT NULL DEFAULT false,
    strict boolean NOT NULL DEFAULT true,
    safety_snapshot boolean NOT NULL DEFAULT true,
    requested_by text NOT NULL,
    status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed')),
    progress smallint,
    progress_step text NOT NULL DEFAULT '',
    error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS jobs_one_active ON jobs (database) WHERE status IN ('queued', 'running');
CREATE TABLE IF NOT EXISTS schedules (
    database text PRIMARY KEY,
    owner_role text NOT NULL,
    cron text NOT NULL,
    next_run timestamptz NOT NULL,
    updated_by text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS uploads (
    id bigserial PRIMARY KEY,
    role_name text NOT NULL,
    file_name text NOT NULL,
    size_bytes bigint NOT NULL,
    mtime timestamptz,
    sha256 text,
    verified_by text NOT NULL DEFAULT '',
    uploaded_by text NOT NULL,
    keep boolean NOT NULL DEFAULT false,
    first_seen timestamptz NOT NULL DEFAULT now(),
    UNIQUE (role_name, file_name)
);
CREATE TABLE IF NOT EXISTS settings (
    key text PRIMARY KEY,
    value text NOT NULL
);
-- jobs from before the column existed count as notified, new ones start unnotified
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS notified boolean NOT NULL DEFAULT true;
ALTER TABLE jobs ALTER COLUMN notified SET DEFAULT false;
ALTER TABLE role_logins ADD COLUMN IF NOT EXISTS auth text NOT NULL DEFAULT 'password' CHECK (auth IN ('password', 'apppw'));`
