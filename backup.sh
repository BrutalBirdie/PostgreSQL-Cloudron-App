#!/bin/bash

set -eu

source /app/pkg/common.sh

readonly tmp_dir="${DUMP_DIR}.new"

rm -rf "${tmp_dir}"
mkdir -p "${tmp_dir}"

echo "==> Dumping roles"
gosu postgres pg_dumpall -h "${PG_SOCKET_DIR}" -U postgres --globals-only > "${tmp_dir}/globals.sql"

# dump files are numbered, the database name is inside the dump (--create)
i=0
while IFS= read -r db; do
    i=$((i + 1))
    echo "==> Dumping database ${db}"
    gosu postgres pg_dump -h "${PG_SOCKET_DIR}" -U postgres --format=custom --create --dbname="${db}" > "${tmp_dir}/$(printf '%04d' "${i}").dump"
done < <(psql_admin -d postgres -At -c "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate AND datname <> 'postgres' AND NOT starts_with(datname, 'pgpanel_') ORDER BY datname")

rm -rf "${DUMP_DIR}"
mv "${tmp_dir}" "${DUMP_DIR}"
chown -R cloudron:cloudron "${DUMP_DIR}"
chmod 0700 "${DUMP_DIR}"

echo "==> Backup dump complete (${i} databases)"
