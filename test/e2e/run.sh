#!/bin/bash
# End-to-end test: fresh install, real browser, mock OIDC, PostgreSQL over TLS,
# backup and restore. Usage: test/e2e/run.sh   (needs Docker)
# SCREENSHOTS=1 also writes the store screenshots to screenshots/

set -eu

cd "$(dirname "$0")"
readonly root=$(cd ../.. && pwd)
readonly img=pgapp:e2e
readonly net=pge2e
readonly app=pge2e-app
readonly mock=pge2e-mock
readonly work=$(mktemp -d)
failures=0

cleanup() {
    [[ -n "${KEEP:-}" ]] || cleanup_containers
    rm -rf "${work}"
}
cleanup_containers() {
    docker rm -f "${app}" "${mock}" >/dev/null 2>&1 || true
    docker volume rm pge2e-data pge2e-pg >/dev/null 2>&1 || true
    docker network rm "${net}" >/dev/null 2>&1 || true
}
cleanup_containers
trap cleanup EXIT

pass() { echo "PASS [shell] $1"; }
fail() { echo "FAIL [shell] $1 :: $2"; failures=$((failures + 1)); }

expect() { # expect <name> <regex> <output>
    if [[ "$3" =~ $2 ]]; then pass "$1"; else fail "$1" "${3:0:300}"; fi
}

browser() {
    docker run --rm --network "container:${app}" -u "$(id -u):$(id -g)" -e HOME=/tmp -e APP_IP="${app_ip}" -v "${PWD}:/e2e" -v "${work}:/work" -w /e2e \
        mcr.microsoft.com/playwright:v1.63.0-noble node e2e.mjs "$1" || failures=$((failures + 1))
}

pg() { # pg <password> <user> <database> <sql> [extra conninfo]
    docker run --rm --network "container:${app}" -v "${work}/certs:/certs:ro" -e PGPASSWORD="$1" -e PGCONNECT_TIMEOUT=5 "${img}" \
        psql "host=pg.test hostaddr=${app_ip} port=5432 sslmode=verify-full sslrootcert=/certs/tls_cert.pem user=$2 dbname=$3 ${5:-}" -XAtc "$4" 2>&1 || true
}

superuser() {
    docker exec "${app}" gosu postgres psql -h /var/lib/postgresql/run -XAtc "$1" "${2:-postgres}"
}

wait_healthy() {
    for _ in $(seq 1 60); do
        docker exec "${app}" curl -sf http://localhost:8000/healthz >/dev/null 2>&1 && return 0
        sleep 1
    done
    docker logs "${app}" | tail -30
    return 1
}

app_run() {
    docker run -d --name "${app}" --network "${net}" --read-only --tmpfs /run --tmpfs /tmp \
        -v pge2e-data:/app/data -v pge2e-pg:/var/lib/postgresql -v "${work}/certs:/etc/certs:ro" \
        -e CLOUDRON_APP_DOMAIN=pg.test -e CLOUDRON_APP_ORIGIN=http://localhost:8000 -e POSTGRES_PORT=5432 \
        -e CLOUDRON_OIDC_ISSUER="http://${mock}:8080/default" -e CLOUDRON_OIDC_CLIENT_ID=pgpanel -e CLOUDRON_OIDC_CLIENT_SECRET=secret \
        "${img}" >/dev/null
}

echo "==> Building"
docker build -q -t "${img}" "${root}" >/dev/null
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "${PWD}:/e2e" -w /e2e mcr.microsoft.com/playwright:v1.63.0-noble npm install --no-audit --no-fund --silent

mkdir -p "${work}/certs"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "${work}/certs/tls_key.pem" -out "${work}/certs/tls_cert.pem" -days 2 \
    -subj "/CN=pg.test" -addext "subjectAltName=DNS:pg.test" 2>/dev/null
chmod 0644 "${work}/certs/"*
chmod 0777 "${work}"

docker network create "${net}" >/dev/null
docker run -d --name "${mock}" --network "${net}" -e JSON_CONFIG='{"interactiveLogin":true}' ghcr.io/navikt/mock-oauth2-server:6.0.3 >/dev/null

echo "==> Fresh install"
app_run
wait_healthy
readonly app_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${net}\").IPAddress}}" "${app}")
expect "env.sh created on first start" "PG_MAX_SNAPSHOTS=7" "$(docker exec "${app}" cat /app/data/env.sh)"
expect "no remote access before allowlist" "rejects connection" "$(pg x e2e_bob e2e_bob 'select 1')"

browser admin
bob_pw=$(yq -p json -oy '.bobPassword' "${work}/state.json")
eve_pw=$(yq -p json -oy '.evePassword' "${work}/state.json")

echo "==> PostgreSQL access"
expect "bob connects with TLS" "^TLSv1.3$" "$(pg "${bob_pw}" e2e_bob e2e_bob 'select version from pg_stat_ssl where pid = pg_backend_pid()')"
expect "bob creates data" "INSERT 0 3" "$(pg "${bob_pw}" e2e_bob e2e_bob 'create table t(x int); insert into t values (1),(2),(3)')"
expect "plain connection rejected" "no encryption" "$(pg "${bob_pw}" e2e_bob e2e_bob 'select 1' 'sslmode=disable')"
expect "TLS 1.2 rejected" "SSL|ssl" "$(pg "${bob_pw}" e2e_bob e2e_bob 'select 1' 'ssl_max_protocol_version=TLSv1.2')"
expect "bob cannot open eve database" "CONNECT privilege" "$(pg "${bob_pw}" e2e_bob e2e_eve 'select 1')"
expect "bob cannot open postgres database" "CONNECT privilege" "$(pg "${bob_pw}" e2e_bob postgres 'select 1')"
expect "bob cannot open pgpanel database" "CONNECT privilege" "$(pg "${bob_pw}" e2e_bob pgpanel 'select 1')"
expect "bob cannot create databases with SQL" "permission denied" "$(pg "${bob_pw}" e2e_bob e2e_bob 'create database sneaky')"
expect "bob cannot run programs" "permission denied|must be superuser" "$(pg "${bob_pw}" e2e_bob e2e_bob "copy (select 1) to program 'id'")"
expect "postgres superuser rejected remotely" "rejects connection" "$(pg x postgres postgres 'select 1')"
expect "pgpanel rejected remotely" "rejects connection" "$(pg x pgpanel pgpanel 'select 1')"
expect "eve connects to her database" "^1$" "$(pg "${eve_pw}" e2e_eve e2e_eve 'select 1')"

browser bob1
new_pw=$(yq -p json -oy '.bobPassword' "${work}/state.json")
expect "old password stops working" "password authentication failed" "$(pg "${bob_pw}" e2e_bob e2e_bob 'select 1')"
expect "new password works" "^1,2,3$" "$(pg "${new_pw}" e2e_bob e2e_bob "select string_agg(x::text, ',' order by x) from t")"
expect "self-service database is locked down" "^\{e2e_bob=CTc/e2e_bob\}$" "$(superuser "select datacl from pg_database where datname = 'e2e_bob_two'")"
expect "no database open to PUBLIC" "^0$" "$(superuser "select count(*) from pg_database where not datistemplate and (datacl is null or datacl::text like '%{=%' or datacl::text like '%,=%')")"
expect "password not in logs" "^0$" "$(docker logs "${app}" 2>&1 | grep -c -- "${new_pw}" || true)"

pg "${new_pw}" e2e_bob e2e_bob 'delete from t; insert into t values (99)' >/dev/null
browser bob2
expect "restore brings data back" "^1,2,3$" "$(pg "${new_pw}" e2e_bob e2e_bob "select string_agg(x::text, ',' order by x) from t")"
expect "restored objects owned by bob" "^e2e_bob$" "$(pg "${new_pw}" e2e_bob e2e_bob "select tableowner from pg_tables where tablename = 't'")"

if [[ "${SCREENSHOTS:-}" == "1" ]]; then
    browser screenshots
    mkdir -p "${root}/screenshots"
    cp "${work}/shots/"*.png "${root}/screenshots/"
fi

echo "==> Uploads and import"
mkdir -p "${work}/files"
pg "${new_pw}" e2e_bob e2e_bob 'create table imported_marker(v text); insert into imported_marker values ($$from dump$$)' >/dev/null
docker run --rm --network "container:${app}" -v "${work}/certs:/certs:ro" -e PGPASSWORD="${new_pw}" "${img}" \
    pg_dump --format=custom "host=pg.test hostaddr=${app_ip} sslmode=verify-full sslrootcert=/certs/tls_cert.pem user=e2e_bob dbname=e2e_bob" > "${work}/files/import me.dump"
pg "${new_pw}" e2e_bob e2e_bob 'drop table imported_marker' >/dev/null
printf '\\! touch /tmp/pwned\nselect 1;\n' > "${work}/files/evil.sql"
head -c 3145728 /dev/urandom > "${work}/files/big.bin"
chmod -R a+rX "${work}/files"
browser uploads
# the File Manager copies with the owner of the parent directory
docker exec "${app}" install -o cloudron -g postgres -m 0644 /app/data/env.sh /app/data/uploads/e2e_bob/manual.dump
manual_sha=$(docker exec "${app}" sha256sum /app/data/uploads/e2e_bob/manual.dump | cut -d' ' -f1)
yq -i -p json -o json ".manualSha = \"${manual_sha}\"" "${work}/state.json"
browser uploads2
# change one byte but keep size and mtime, so only the checksum can notice
docker exec "${app}" bash -c 'f=/app/data/uploads/e2e_bob/import_me-1.dump; m=$(stat -c %y "$f"); printf X | dd of="$f" bs=1 seek=200 conv=notrunc status=none; touch -d "$m" "$f"'
browser tampered

pg "${new_pw}" e2e_bob e2e_bob "create table big as select g as id, md5(g::text) || md5((g * 7)::text) as payload from generate_series(1, 3000000) g; create index big_payload on big (payload)" >/dev/null
docker run --rm --network "container:${app}" -v "${work}/certs:/certs:ro" -e PGPASSWORD="${new_pw}" "${img}" \
    pg_dump --format=custom --compress=0 "host=pg.test hostaddr=${app_ip} sslmode=verify-full sslrootcert=/certs/tls_cert.pem user=e2e_bob dbname=e2e_bob" > "${work}/files/big.dump"
chmod a+r "${work}/files/big.dump"
pg "${new_pw}" e2e_bob e2e_bob 'drop table big' >/dev/null
# a client keeps querying while the import runs, it must see the old data until the swap
( for _ in $(seq 1 400); do pg "${new_pw}" e2e_bob e2e_bob 'select v from imported_marker' | head -1; done ) > "${work}/during.log" 2>&1 &
client=$!
browser bigImport
kill "${client}" 2>/dev/null || true
wait "${client}" 2>/dev/null || true
expect "client saw the old data during the import" "^[3-9]|^[1-9][0-9]" "$(grep -c '^from dump$' "${work}/during.log")"
expect "client interrupted only at the swap" "^[0-2]$" "$(grep -vc '^from dump$' "${work}/during.log" || true)"
expect "no staging databases left" "^0$" "$(superuser "select count(*) from pg_database where datname like 'pgpanel\_%'")"
import_job=$(superuser "select max(id) from jobs where kind = 'import'" pgpanel)
steps=$(docker logs "${app}" 2>&1 | grep '"msg":"job step","id":'"${import_job}"',' | while read -r line; do yq -p json -oy '.step' <<<"${line}"; done \
    | sed -E 's/: [0-9.]+ [KMG]?i?B written$//' | uniq | paste -sd '>' -)
steps_pattern='^Checking the SHA-256 of the file>Taking a safety snapshot of the current data>Creating a new database to load into, the current one stays online>Starting pg_restore>.*Processing data for table "public.big">.*Creating INDEX "public.big_payload">Switching to the new database$'
expect "import steps logged in order" "${steps_pattern}" "${steps}"
expect "big import restored all rows" "^3000000$" "$(pg "${new_pw}" e2e_bob e2e_bob 'select count(*) from big')"
expect "progress recorded for the finished job" "Switching to the new database" "$(superuser "select progress_step from jobs where kind = 'import' order by id desc limit 1" pgpanel)"

# a dump that needs an extension tenants may not create fails in all-or-nothing mode
superuser "create database e2e_extsrc" >/dev/null
superuser "create extension file_fdw; create table t(i int); insert into t values (1)" e2e_extsrc >/dev/null
docker exec "${app}" gosu postgres pg_dump -h /var/lib/postgresql/run --format=custom e2e_extsrc > "${work}/files/ext.dump"
chmod a+r "${work}/files/ext.dump"
superuser "drop database e2e_extsrc" >/dev/null
browser failedImport
expect "failed import left the data unchanged" "^from dump$" "$(pg "${new_pw}" e2e_bob e2e_bob 'select v from imported_marker')"
expect "failed import left no staging database" "^0$" "$(superuser "select count(*) from pg_database where datname like 'pgpanel\_%'")"
pg "${new_pw}" e2e_bob e2e_bob 'drop table big' >/dev/null
expect "import loaded the dump" "^from dump$" "$(pg "${new_pw}" e2e_bob e2e_bob 'select v from imported_marker')"
expect "imported objects owned by bob" "^e2e_bob$" "$(pg "${new_pw}" e2e_bob e2e_bob "select tableowner from pg_tables where tablename = 'imported_marker'")"
expect "plain SQL never executed" "^no$" "$(docker exec "${app}" bash -c 'test -e /tmp/pwned && echo yes || echo no')"
upload_perms=$(docker exec "${app}" find /app/data/uploads -mindepth 1 -printf '%y %m %u:%g %p\n')
expect "upload directories setgid, cloudron:postgres" "^$" "$(grep '^d' <<<"${upload_perms}" | grep -v '^d 2750 cloudron:postgres ' || true)"
expect "panel uploads 0640 cloudron:postgres" "f 640 cloudron:postgres /app/data/uploads/e2e_bob/import_me.dump" "${upload_perms}"

superuser "update uploads set first_seen = now() - interval '9 days'" pgpanel >/dev/null
docker restart "${app}" >/dev/null
wait_healthy
sleep 3
remaining=$(docker exec "${app}" ls /app/data/uploads/e2e_bob)
expect "expired uploads deleted" "^import_me.dump$" "${remaining}"

superuser "update schedules set next_run = now() - interval '1 minute'" pgpanel >/dev/null
for _ in $(seq 1 60); do
    [[ "$(superuser "select count(*) from jobs where scheduled and status = 'done'" pgpanel)" -ge 1 ]] && break
    sleep 1
done
browser bob3
browser eve
browser admin2

echo "==> Snapshot file permissions"
perms=$(docker exec "${app}" find /app/data/snapshots -mindepth 1 -printf '%y %m %g %p\n')
expect "snapshot directories setgid, group cloudron" "^$" "$(grep '^d' <<<"${perms}" | grep -v '^d 2770 cloudron ' || true)"
expect "snapshot files 0640, group cloudron" "^$" "$(grep '^f' <<<"${perms}" | grep -v '^f 640 cloudron ' || true)"
expect "snapshot files exist" "f 640 cloudron" "${perms}"

echo "==> PG_ADMINS without new login"
docker exec "${app}" sed -i 's/^export PG_ADMINS=.*/export PG_ADMINS="bob"/' /app/data/env.sh
docker restart "${app}" >/dev/null
wait_healthy
browser bobAdminByEnv

echo "==> Backup and restore"
docker run --rm --network "container:${app}" --read-only --tmpfs /tmp --tmpfs /run -v pge2e-data:/app/data -v pge2e-pg:/var/lib/postgresql \
    "${img}" /app/pkg/backup.sh >"${work}/backup.log" 2>&1 && pass "backup.sh" || fail "backup.sh" "$(tail -5 "${work}/backup.log")"
pg "${new_pw}" e2e_bob e2e_bob 'insert into t values (1000)' >/dev/null
docker stop "${app}" >/dev/null
docker run --rm --read-only --tmpfs /tmp --tmpfs /run -v pge2e-data:/app/data -v pge2e-pg:/var/lib/postgresql \
    "${img}" /app/pkg/restore.sh >"${work}/restore.log" 2>&1 && pass "restore.sh" || fail "restore.sh" "$(tail -5 "${work}/restore.log")"
docker start "${app}" >/dev/null
wait_healthy
expect "data from backup" "^1,2,3$" "$(pg "${new_pw}" e2e_bob e2e_bob "select string_agg(x::text, ',' order by x) from t")"
expect "allowlist survives restore" "${app_ip}" "$(docker exec "${app}" cat /run/pg/hba/pg_hba.conf)"
browser afterRestore

echo "==> Logs"
expect "no panel or worker errors" "^$" "$(docker logs "${app}" 2>&1 | grep '"level":"ERROR"' | grep -v 'the file changed since it was uploaded\|file_fdw' || true)"
expect "no PostgreSQL errors except expected test failures" "^$" "$(docker logs "${app}" 2>&1 | grep -E ' (ERROR|PANIC):' | grep -vE 'permission denied (to create database|to use|for)|must be superuser|role "postgres" already exists|COPY to or from an external program|file_fdw|current transaction is aborted' || true)"

echo
if [[ ${failures} -eq 0 ]]; then
    echo "==> All checks passed"
else
    echo "==> ${failures} failed"
    exit 1
fi
