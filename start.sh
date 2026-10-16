#!/bin/bash

set -eu

source /app/pkg/common.sh

readonly ALLOWLIST_FILE="/app/data/allowed_networks.txt"

mkdir -p /run/nginx "${PG_RUN_DIR}/tls"
chown postgres:postgres "${PG_RUN_DIR}"
pg_prepare_dirs

if [[ ! -f "${PGDATA}/PG_VERSION" ]]; then
    pg_initdb
fi

if [[ ! -f "${ALLOWLIST_FILE}" ]]; then
    cat > "${ALLOWLIST_FILE}" <<'EOF'
# Networks allowed to connect to PostgreSQL from outside, one per line.
# Examples:
#   203.0.113.10
#   198.51.100.0/24
#   2001:db8::/48
# Restart the app after editing. An empty list blocks all remote connections.
EOF
fi

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
hba_file = '${PG_RUN_DIR}/pg_hba.conf'
ident_file = '${PGDATA}/pg_ident.conf'

listen_addresses = '*'
port = 5432
unix_socket_directories = '${PG_SOCKET_DIR}'
unix_socket_permissions = 0770
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

echo "==> Generating pg_hba.conf"
{
    echo "local   all  postgres                 peer"
    echo "local   all  all                      reject"
    echo "host    all  postgres  0.0.0.0/0      reject"
    echo "host    all  postgres  ::/0           reject"
    while read -r line; do
        cidr="${line%%#*}"
        cidr="${cidr//[[:space:]]/}"
        [[ -z "${cidr}" ]] && continue
        if [[ "${cidr}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            cidr="${cidr}/32"
        elif [[ "${cidr}" =~ ^[0-9a-fA-F:]+$ && "${cidr}" == *:* ]]; then
            cidr="${cidr}/128"
        fi
        if [[ ! "${cidr}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ && ! "${cidr}" =~ ^[0-9a-fA-F:]+/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8])$ ]]; then
            echo "==> Ignoring invalid allowlist entry: ${line}" >&2
            continue
        fi
        [[ "${cidr}" == "0.0.0.0/0" || "${cidr}" == "::/0" ]] && echo "==> WARNING: allowlist entry ${cidr} opens PostgreSQL to the whole internet" >&2
        echo "==> Allowing ${cidr}" >&2
        echo "hostssl all  +tenants  ${cidr}  scram-sha-256"
    done < "${ALLOWLIST_FILE}"
    echo "host    all  all       0.0.0.0/0      reject"
    echo "host    all  all       ::/0           reject"
} > "${PG_RUN_DIR}/pg_hba.conf"
chown postgres:postgres "${PG_RUN_DIR}/postgresql.conf" "${PG_RUN_DIR}/pg_hba.conf"

echo "==> Applying baseline privileges"
pg_start_local
psql_admin -d postgres <<'EOF'
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'tenants') THEN
        CREATE ROLE tenants NOLOGIN;
    END IF;
END $$;
REVOKE ALL ON DATABASE postgres FROM PUBLIC;
REVOKE ALL ON DATABASE template1 FROM PUBLIC;
EOF
pg_stop_local

chown -R cloudron:cloudron /app/data

echo "==> Starting supervisor"
exec /usr/bin/supervisord --configuration /etc/supervisor/supervisord.conf --nodaemon -i PostgreSQL
