#!/bin/bash

readonly PG_BIN="/usr/lib/postgresql/18/bin"
readonly PG_ROOT="/var/lib/postgresql"
PGDATA="${PG_ROOT}/18/data"
# socket lives in the persistent dir so backupCommand's container can reach it
readonly PG_SOCKET_DIR="${PG_ROOT}/run"
readonly PG_RUN_DIR="/run/pg"
readonly DUMP_DIR="/app/data/dumps"

pg_prepare_dirs() {
    mkdir -p "${PG_ROOT}/18" "${PG_SOCKET_DIR}"
    chown postgres:postgres "${PG_ROOT}" "${PG_ROOT}/18" "${PG_SOCKET_DIR}"
    chmod 0755 "${PG_ROOT}" "${PG_SOCKET_DIR}"
    [[ -d "${PGDATA}" ]] && chown -R postgres:postgres "${PGDATA}" && chmod 0700 "${PGDATA}"
    return 0
}

pg_initdb() {
    echo "==> Initializing new cluster"
    gosu postgres "${PG_BIN}/initdb" -D "${PGDATA}" --auth-local=peer --auth-host=scram-sha-256 --data-checksums --encoding=UTF8 --locale=C.UTF-8 --username=postgres
}

# socket-only instance for maintenance (setup, restore). Nothing listens on TCP.
pg_start_local() {
    gosu postgres "${PG_BIN}/pg_ctl" -D "${PGDATA}" -w -t 120 -l /tmp/pg-maintenance.log \
        -o "-c listen_addresses='' -c unix_socket_directories='${PG_SOCKET_DIR}'" start \
        || { cat /tmp/pg-maintenance.log; return 1; }
}

pg_stop_local() {
    gosu postgres "${PG_BIN}/pg_ctl" -D "${PGDATA}" -w -t 300 -m fast stop
}

# lets the panel manage tenant roles that were created outside of it (pgtenant.sh, restores)
pg_grant_tenants_to_panel() {
    psql_admin -q -d postgres <<'EOF'
SELECT format('GRANT %I TO pgpanel WITH ADMIN TRUE, INHERIT FALSE, SET TRUE', r.rolname)
FROM pg_roles r JOIN pg_auth_members m ON m.member = r.oid JOIN pg_roles g ON g.oid = m.roleid AND g.rolname = 'tenants'
WHERE r.rolname <> 'pgpanel' \gexec
EOF
}

psql_admin() {
    gosu postgres psql -h "${PG_SOCKET_DIR}" -U postgres -X -v ON_ERROR_STOP=1 "$@"
}
