#!/bin/bash

set -eu

source /app/pkg/common.sh

readonly ALLOWLIST_FILE="/app/data/allowed_networks.txt"

mkdir -p /run/nginx "${PG_RUN_DIR}/tls" "${PG_RUN_DIR}/hba"
chown postgres:postgres "${PG_RUN_DIR}" "${PG_RUN_DIR}/tls"
chown cloudron:cloudron "${PG_RUN_DIR}/hba"
pg_prepare_dirs

if [[ ! -f "${PGDATA}/PG_VERSION" ]]; then
    pg_initdb
fi

if [[ ! -f /app/data/env.sh ]]; then
    cat > /app/data/env.sh <<'EOF'
# Restart the app after changing these.
# Members of these Cloudron groups are admins in the panel, separated by commas.
export PG_ADMIN_GROUP=postgres-admins
# Cloudron usernames that are always admins, separated by commas.
export PG_ADMINS=""
# Snapshots kept per database and type (manual, scheduled, before restore), oldest are deleted first.
export PG_MAX_SNAPSHOTS=7
# Uploaded dump files are deleted after this many days unless marked to keep.
export PG_UPLOAD_RETENTION_DAYS=8
EOF
fi
source /app/data/env.sh

if [[ ! -f "${ALLOWLIST_FILE}" ]]; then
    printf '# Networks allowed to connect to PostgreSQL from outside, one per line.\n# Managed by the admin panel. Manual edits need an app restart.\n' > "${ALLOWLIST_FILE}"
fi

chown -R cloudron:cloudron /app/data
readonly SNAPSHOT_DIR="${PG_ROOT}/snapshots"
mkdir -p "${SNAPSHOT_DIR}"
# written by the worker (postgres), read and deleted by the panel (cloudron)
chown -R postgres:cloudron "${SNAPSHOT_DIR}"
find "${SNAPSHOT_DIR}" -type d -exec chmod 2770 {} +
find "${SNAPSHOT_DIR}" -type f -exec chmod 0640 {} +
mkdir -p /app/data/uploads
# written and deleted by the panel (cloudron), read by the worker (postgres)
chown -R cloudron:postgres /app/data/uploads
find /app/data/uploads -type d -exec chmod 2750 {} +
find /app/data/uploads -type f -exec chmod 0640 {} +

echo "==> Copying TLS certificate"
if [[ ! -f /etc/certs/tls_cert.pem || ! -f /etc/certs/tls_key.pem ]]; then
    echo "==> /etc/certs/tls_cert.pem missing, refusing to start without TLS"
    exit 1
fi
install -o postgres -g postgres -m 0644 /etc/certs/tls_cert.pem "${PG_RUN_DIR}/tls/server.crt"
install -o postgres -g postgres -m 0600 /etc/certs/tls_key.pem "${PG_RUN_DIR}/tls/server.key"

if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
    memory_limit=$(cat /sys/fs/cgroup/memory.max)
    [[ "${memory_limit}" == "max" ]] && memory_limit=$((2 * 1024 * 1024 * 1024))
else
    memory_limit=$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)
fi
memory_mb=$((memory_limit / 1024 / 1024))

echo "==> Generating postgresql.conf (memory limit ${memory_mb}MB)"
cat > "${PG_RUN_DIR}/postgresql.conf" <<EOF
data_directory = '${PGDATA}'
hba_file = '${PG_RUN_DIR}/hba/pg_hba.conf'
ident_file = '${PG_RUN_DIR}/pg_ident.conf'

listen_addresses = '*'
port = 5432
unix_socket_directories = '${PG_SOCKET_DIR}'
max_connections = 100
authentication_timeout = 10s
tcp_keepalives_idle = 60

ssl = on
ssl_cert_file = '${PG_RUN_DIR}/tls/server.crt'
ssl_key_file = '${PG_RUN_DIR}/tls/server.key'
ssl_min_protocol_version = 'TLSv1.3'
password_encryption = 'scram-sha-256'

# https://www.postgresql.org/docs/18/auth-delay.html
shared_preload_libraries = 'auth_delay'
auth_delay.milliseconds = 500

shared_buffers = $((memory_mb / 4))MB
effective_cache_size = $((memory_mb / 2))MB
maintenance_work_mem = $((memory_mb / 16))MB

log_destination = 'stderr'
logging_collector = off
log_line_prefix = '%m [%p] %q%u@%d %h '
log_connections = 'authorization'
# never echo statements into the app log, they can contain passwords or tenant data
log_min_error_statement = panic
log_timezone = 'UTC'
timezone = 'UTC'
EOF
# the snapshot worker runs as OS user postgres and dumps/restores as the database owner role
printf 'panel   cloudron  pgpanel\nworker  postgres  +tenants\n' > "${PG_RUN_DIR}/pg_ident.conf"
chown postgres:postgres "${PG_RUN_DIR}/postgresql.conf" "${PG_RUN_DIR}/pg_ident.conf"

echo "==> Generating pg_hba.conf"
gosu cloudron:cloudron /app/code/panel render-hba --allowlist "${ALLOWLIST_FILE}" --out "${PG_RUN_DIR}/hba/pg_hba.conf"

echo "==> Applying baseline privileges"
pg_start_local
psql_admin -d postgres <<'EOF'
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'tenants') THEN
        CREATE ROLE tenants NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'pgpanel') THEN
        CREATE ROLE pgpanel LOGIN;
    END IF;
END $$;
ALTER ROLE pgpanel LOGIN NOSUPERUSER CREATEDB CREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD NULL;
-- roles created by pgpanel are granted back to it with SET, needed for CREATE DATABASE ... OWNER
ALTER ROLE pgpanel SET createrole_self_grant = 'set';
GRANT tenants TO pgpanel WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
-- database sizes in the panel - https://www.postgresql.org/docs/18/functions-admin.html#FUNCTIONS-ADMIN-DBOBJECT
GRANT pg_read_all_stats TO pgpanel;

SELECT 'CREATE DATABASE pgpanel OWNER pgpanel' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'pgpanel') \gexec
REVOKE ALL ON DATABASE pgpanel FROM PUBLIC;
REVOKE ALL ON DATABASE postgres FROM PUBLIC;
REVOKE ALL ON DATABASE template1 FROM PUBLIC;
-- a database with default privileges lets every role connect, e.g. after an interrupted create
SELECT format('REVOKE ALL ON DATABASE %1$I FROM PUBLIC; GRANT CONNECT, TEMPORARY ON DATABASE %1$I TO %2$I', d.datname, r.rolname)
FROM pg_database d JOIN pg_roles r ON r.oid = d.datdba WHERE d.datacl IS NULL AND NOT d.datistemplate \gexec
EOF
# function and view privileges are per database, the panel only connects to pgpanel
psql_admin -d pgpanel <<'EOF'
GRANT EXECUTE ON FUNCTION pg_reload_conf() TO pgpanel;
GRANT EXECUTE ON FUNCTION pg_hba_file_rules() TO pgpanel;
GRANT SELECT ON pg_hba_file_rules TO pgpanel;
EOF
pg_grant_tenants_to_panel
pg_stop_local

echo "==> Starting supervisor"
exec /usr/bin/supervisord --configuration /etc/supervisor/supervisord.conf --nodaemon -i PostgreSQL
