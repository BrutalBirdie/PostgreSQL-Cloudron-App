#!/bin/bash

set -eu

source /app/pkg/common.sh

if [[ ! -f "${DUMP_DIR}/globals.sql" ]]; then
    echo "==> No dumps in ${DUMP_DIR}, keeping existing cluster"
    exit 0
fi

readonly live_dir="${PGDATA}"
readonly new_dir="${PGDATA}.restore"

echo "==> Restoring dumps into a new cluster"
rm -rf "${new_dir}"
pg_prepare_dirs
PGDATA="${new_dir}" pg_initdb
PGDATA="${new_dir}" pg_start_local

# globals.sql re-creates the postgres role which already exists, that error is expected
gosu postgres psql -h "${PG_SOCKET_DIR}" -U postgres -X -q -d postgres < "${DUMP_DIR}/globals.sql"

for dump in "${DUMP_DIR}"/*.dump; do
    [[ -f "${dump}" ]] || continue
    echo "==> Restoring ${dump}"
    gosu postgres pg_restore -h "${PG_SOCKET_DIR}" -U postgres --create --exit-on-error --dbname=postgres < "${dump}" \
        || { PGDATA="${new_dir}" pg_stop_local; rm -rf "${new_dir}"; echo "==> Restore failed, existing cluster left untouched"; exit 1; }
done

PGDATA="${new_dir}" pg_stop_local

echo "==> Swapping in restored cluster"
rm -rf "${live_dir}"
mv "${new_dir}" "${live_dir}"

echo "==> Restore complete"
