#!/bin/bash
# End-to-end test: fresh install, real browser, mock OIDC, PostgreSQL over TLS,
# backup and restore. Usage: test/e2e/run.sh   (needs Docker)
# SCREENSHOTS=1 also writes the store screenshots to screenshots/
# ARTIFACTS=<dir> keeps step screenshots, store screenshots, failed pages and the app log

set -eu

cd "$(dirname "$0")"
readonly root=$(cd ../.. && pwd)
readonly img=pgapp:e2e
readonly net=pge2e
readonly app=pge2e-app
readonly mock=pge2e-mock
readonly scim=pge2e-scim
readonly smtp=pge2e-smtp
readonly work=$(mktemp -d)
failures=0

cleanup() {
    if [[ -n "${ARTIFACTS:-}" ]]; then
        mkdir -p "${ARTIFACTS}"
        docker logs "${app}" > "${ARTIFACTS}/app.log" 2>&1 || true
        cp -R "${work}/steps" "${work}/shots" "${work}/"fail-*.html "${ARTIFACTS}/" 2>/dev/null || true
    fi
    if [[ -n "${KEEP:-}" ]]; then
        echo "==> Kept containers and ${work}"
    else
        cleanup_containers
        rm -rf "${work}"
    fi
}
cleanup_containers() {
    docker rm -f "${app}" "${mock}" "${scim}" "${smtp}" >/dev/null 2>&1 || true
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
        -e CLOUDRON_SCIM_ORIGIN="http://${scim}:8080" -e CLOUDRON_SCIM_TOKEN=scimtoken -e PANEL_SCIM_CACHE=1s -e PANEL_ACCESS_SYNC=3s \
        -e CLOUDRON_MAIL_SMTP_SERVER=mail.test -e CLOUDRON_MAIL_STARTTLS_PORT=2587 -e CLOUDRON_MAIL_SMTP_USERNAME=app -e CLOUDRON_MAIL_SMTP_PASSWORD=mailpass \
        -e CLOUDRON_MAIL_FROM=pg.app@pg.test -e PANEL_NOTIFY_INTERVAL=2s -e SSL_CERT_FILE=/etc/certs/mail_cert.pem \
        "${img}" >/dev/null
}

echo "==> Building"
docker build -q -t "${img}" "${root}" >/dev/null
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -v "${PWD}:/e2e" -w /e2e mcr.microsoft.com/playwright:v1.63.0-noble npm install --no-audit --no-fund --silent

mkdir -p "${work}/certs"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "${work}/certs/tls_key.pem" -out "${work}/certs/tls_cert.pem" -days 2 \
    -subj "/CN=pg.test" -addext "subjectAltName=DNS:pg.test" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -keyout "${work}/certs/mail_key.pem" -out "${work}/certs/mail_cert.pem" -days 2 \
    -subj "/CN=mail.test" -addext "subjectAltName=DNS:mail.test" 2>/dev/null
chmod 0644 "${work}/certs/"*
chmod 0777 "${work}"

docker network create "${net}" >/dev/null
docker run -d --name "${mock}" --network "${net}" -e JSON_CONFIG='{"interactiveLogin":true}' ghcr.io/navikt/mock-oauth2-server:6.0.3 >/dev/null
scim_users() { # scim_users <carol's groups as JSON array>
    cat > "${work}/scim.json" <<EOF
{
  "groups": [{"id": "g-admins", "displayName": "postgres-admins"}, {"id": "g-team", "displayName": "dbteam"}, {"id": "g-ops", "displayName": "ops"}],
  "users": [
    {"userName": "ann", "displayName": "Ann Admin", "groups": ["g-admins"]},
    {"userName": "bob", "displayName": "Bob Builder", "groups": []},
    {"userName": "carol", "displayName": "Carol Team", "groups": $1},
    {"userName": "eve", "displayName": "Eve", "groups": ["g-ops"]}
  ]
}
EOF
}
scim_users '["g-team"]'
docker run -d --name "${scim}" --network "${net}" -e SCIM_TOKEN=scimtoken -v "${PWD}:/e2e:ro" -v "${work}:/work:ro" -w /e2e \
    mcr.microsoft.com/playwright:v1.63.0-noble node scim-mock.mjs >/dev/null
docker run -d --name "${smtp}" --network "${net}" --network-alias mail.test -u "$(id -u):$(id -g)" -v "${PWD}:/e2e:ro" -v "${work}:/work" -w /e2e \
    mcr.microsoft.com/playwright:v1.63.0-noble node smtp-mock.mjs >/dev/null

mails() { # mails <recipient> <subject regex>: number of matching messages
    grep -lE "^Subject: $2" "${work}"/mail/*-"$1".eml 2>/dev/null | wc -l
}
mail_text() { # mail_text <recipient>: all messages with quoted-printable soft line breaks removed
    cat "${work}"/mail/*-"$1".eml 2>/dev/null | sed -z 's/=\n//g'
}
wait_mail() { # wait_mail <recipient> <regex>
    for _ in $(seq 1 30); do
        grep -qE "$2" <<<"$(mail_text "$1")" && return 0
        sleep 1
    done
    return 1
}

echo "==> Fresh install"
app_run
wait_healthy
readonly app_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"${net}\").IPAddress}}" "${app}")
expect "env.sh created on first start" "PG_MAX_SNAPSHOTS=7" "$(docker exec "${app}" cat /app/data/env.sh)"
expect "no remote access before allowlist" "rejects connection" "$(pg x e2e_bob e2e_bob 'select 1')"

browser admin
expect "test mail delivered" "^1$" "$(mails dba@example.test 'PostgreSQL: test mail')"
browser bobLogin
browser eveLogin
bob_pw=$(yq -p json -oy '.bobPassword' "${work}/state.json")
eve_pw=$(yq -p json -oy '.evePassword' "${work}/state.json")

echo "==> PostgreSQL access"
expect "bob connects" "^1$" "$(pg "${bob_pw}" e2e_bob.bob e2e_bob 'select 1')"
expect "bob's connection used TLS 1.3" "protocol=TLSv1.3" "$(docker logs "${app}" 2>&1 | grep 'connection authorized: user=e2e_bob.bob' | tail -1)"
expect "bob creates data" "INSERT 0 3" "$(pg "${bob_pw}" e2e_bob.bob e2e_bob 'create table t(x int); insert into t values (1),(2),(3)')"
expect "plain connection rejected" "no encryption" "$(pg "${bob_pw}" e2e_bob.bob e2e_bob 'select 1' 'sslmode=disable')"
expect "TLS 1.2 rejected" "SSL|ssl" "$(pg "${bob_pw}" e2e_bob.bob e2e_bob 'select 1' 'ssl_max_protocol_version=TLSv1.2')"
expect "bob cannot open eve database" "CONNECT privilege" "$(pg "${bob_pw}" e2e_bob.bob e2e_eve 'select 1')"
expect "bob cannot open postgres database" "CONNECT privilege" "$(pg "${bob_pw}" e2e_bob.bob postgres 'select 1')"
expect "bob cannot open pgpanel database" "CONNECT privilege" "$(pg "${bob_pw}" e2e_bob.bob pgpanel 'select 1')"
expect "bob cannot create databases with SQL" "permission denied" "$(pg "${bob_pw}" e2e_bob.bob e2e_bob 'create database sneaky')"
expect "bob cannot run programs" "permission denied|must be superuser" "$(pg "${bob_pw}" e2e_bob.bob e2e_bob "copy (select 1) to program 'id'")"
expect "postgres superuser rejected remotely" "rejects connection" "$(pg x postgres postgres 'select 1')"
expect "pgpanel rejected remotely" "rejects connection" "$(pg x pgpanel pgpanel 'select 1')"
expect "eve connects to her database" "^1$" "$(pg "${eve_pw}" e2e_eve.eve e2e_eve 'select 1')"
expect "shared role has no password" "password authentication failed" "$(pg x e2e_bob e2e_bob 'select 1')"
expect "tenant cannot create dblink" "permission denied|must be|not allowed" "$(pg "${bob_pw}" e2e_bob.bob e2e_bob 'create extension dblink')"
expect "tenant cannot create postgres_fdw" "permission denied|must be|not allowed" "$(pg "${bob_pw}" e2e_bob.bob e2e_bob 'create extension postgres_fdw')"

echo "==> Group owners and per-user logins"
browser carol
carol_pw=$(yq -p json -oy '.carolPassword' "${work}/state.json")
expect "carol connects with her own login" "^CREATE TABLE$" "$(pg "${carol_pw}" e2e_bob.carol e2e_bob 'create table carol_t(i int)')"
expect "carol's table belongs to the shared role" "^e2e_bob$" "$(pg "${bob_pw}" e2e_bob.bob e2e_bob "select tableowner from pg_tables where tablename = 'carol_t'")"
expect "bob uses carol's table" "^0$" "$(pg "${bob_pw}" e2e_bob.bob e2e_bob 'select count(*) from carol_t')"
pg "${bob_pw}" e2e_bob.bob e2e_bob 'drop table carol_t' >/dev/null
scim_users '[]'
for _ in $(seq 1 30); do
    [[ "$(superuser "select count(*) from pg_roles where rolname = 'e2e_bob.carol'")" == "0" ]] && break
    sleep 1
done
expect "carol's login removed after leaving the group" "password authentication failed|does not exist|rejects connection" "$(pg "${carol_pw}" e2e_bob.carol e2e_bob 'select 1')"
expect "bob's login still works" "^1$" "$(pg "${bob_pw}" e2e_bob.bob e2e_bob 'select 1')"
expect "removal audited" "login.remove" "$(superuser "select action from audit_log where target = 'e2e_bob.carol'" pgpanel)"
browser carolGone
scim_users '["g-team"]'

# a directory outage must not revoke anything, otherwise every client would be locked out
outage_before=$(docker logs "${app}" 2>&1 | grep -c 'directory is not reachable' || true)
docker stop "${scim}" >/dev/null
outage_seen=0
for _ in $(seq 1 40); do
    outage_seen=$(( $(docker logs "${app}" 2>&1 | grep -c 'directory is not reachable' || true) - outage_before ))
    [[ ${outage_seen} -ge 2 ]] && break
    sleep 1
done
expect "outage noticed by the access sync" "^[2-9]|^[1-9][0-9]" "${outage_seen}"
expect "no login removed while SCIM is down" "^1$" "$(superuser "select count(*) from pg_roles where rolname = 'e2e_bob.bob'")"
expect "bob still connects while SCIM is down" "^1$" "$(pg "${bob_pw}" e2e_bob.bob e2e_bob 'select 1')"
docker start "${scim}" >/dev/null



browser bob1
new_pw=$(yq -p json -oy '.bobPassword' "${work}/state.json")
expect "old password stops working" "password authentication failed" "$(pg "${bob_pw}" e2e_bob.bob e2e_bob 'select 1')"
expect "new password works" "^1,2,3$" "$(pg "${new_pw}" e2e_bob.bob e2e_bob "select string_agg(x::text, ',' order by x) from t")"
expect "self-service database is locked down" "^\{e2e_bob=CTc/e2e_bob\}$" "$(superuser "select datacl from pg_database where datname = 'e2e_bob_two'")"
expect "no database open to PUBLIC" "^0$" "$(superuser "select count(*) from pg_database where not datistemplate and (datacl is null or datacl::text like '%{=%' or datacl::text like '%,=%')")"
expect "password not in logs" "^0$" "$(docker logs "${app}" 2>&1 | grep -c -- "${new_pw}" || true)"

pg "${new_pw}" e2e_bob.bob e2e_bob 'delete from t; insert into t values (99)' >/dev/null
browser bob2
expect "restore brings data back" "^1,2,3$" "$(pg "${new_pw}" e2e_bob.bob e2e_bob "select string_agg(x::text, ',' order by x) from t")"
expect "restored objects owned by bob" "^e2e_bob$" "$(pg "${new_pw}" e2e_bob.bob e2e_bob "select tableowner from pg_tables where tablename = 't'")"

echo "==> Snapshot storage"
snap_file=$(docker exec "${app}" find /var/lib/postgresql/snapshots -name '*.dump' | head -1)
expect "snapshots stored outside /app/data" "^/var/lib/postgresql/snapshots/e2e_bob/" "${snap_file}"
expect "no snapshot directory in /app/data" "^no$" "$(docker exec "${app}" bash -c 'test -e /app/data/snapshots && echo yes || echo no')"
expect "snapshots use zstd" "zstd" "$(docker exec "${app}" gosu postgres pg_restore -l "${snap_file}" | grep -i compression)"
expect "snapshots quote all identifiers" 'CREATE TABLE "public"\."t"' "$(docker exec "${app}" gosu postgres pg_restore -f - "${snap_file}" | grep 'CREATE TABLE')"
expect "backups quote all identifiers" 'CREATE ROLE "e2e_bob"' "$(docker run --rm --network "container:${app}" -v pge2e-pg:/var/lib/postgresql "${img}" gosu postgres pg_dumpall -h /var/lib/postgresql/run --globals-only --quote-all-identifiers | grep 'CREATE ROLE "e2e_bob"')"

if [[ "${SCREENSHOTS:-}" == "1" || -n "${ARTIFACTS:-}" ]]; then
    browser screenshots
fi
if [[ "${SCREENSHOTS:-}" == "1" ]]; then
    mkdir -p "${root}/screenshots"
    cp "${work}/shots/"*.png "${root}/screenshots/"
fi

echo "==> Uploads and import"
mkdir -p "${work}/files"
pg "${new_pw}" e2e_bob.bob e2e_bob 'create table imported_marker(v text); insert into imported_marker values ($$from dump$$)' >/dev/null
docker run --rm --network "container:${app}" -v "${work}/certs:/certs:ro" -e PGPASSWORD="${new_pw}" "${img}" \
    pg_dump --format=custom "host=pg.test hostaddr=${app_ip} sslmode=verify-full sslrootcert=/certs/tls_cert.pem user=e2e_bob.bob dbname=e2e_bob" > "${work}/files/import me.dump"
pg "${new_pw}" e2e_bob.bob e2e_bob 'drop table imported_marker' >/dev/null
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

pg "${new_pw}" e2e_bob.bob e2e_bob "create table big as select g as id, md5(g::text) || md5((g * 7)::text) as payload from generate_series(1, 3000000) g; create index big_payload on big (payload)" >/dev/null
docker run --rm --network "container:${app}" -v "${work}/certs:/certs:ro" -e PGPASSWORD="${new_pw}" "${img}" \
    pg_dump --format=custom --compress=0 "host=pg.test hostaddr=${app_ip} sslmode=verify-full sslrootcert=/certs/tls_cert.pem user=e2e_bob.bob dbname=e2e_bob" > "${work}/files/big.dump"
chmod a+r "${work}/files/big.dump"
pg "${new_pw}" e2e_bob.bob e2e_bob 'drop table big' >/dev/null
# a client keeps querying while the import runs, it must see the old data until the swap
( for _ in $(seq 1 400); do pg "${new_pw}" e2e_bob.bob e2e_bob 'select v from imported_marker' | head -1; done ) > "${work}/during.log" 2>&1 &
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
expect "big import restored all rows" "^3000000$" "$(pg "${new_pw}" e2e_bob.bob e2e_bob 'select count(*) from big')"
browser bigSnapshot
for c in gzip zstd; do
    t0=$(date +%s.%N)
    docker exec "${app}" gosu postgres pg_dump -h /var/lib/postgresql/run --format=custom --compress="${c}" e2e_bob > "${work}/cmp.${c}"
    t1=$(date +%s.%N)
    echo "INFO 3 million rows, ${c}: $(du -k "${work}/cmp.${c}" | cut -f1) KiB in $(echo "${t1} - ${t0}" | bc) s"
done
expect "progress recorded for the finished job" "Switching to the new database" "$(superuser "select progress_step from jobs where kind = 'import' order by id desc limit 1" pgpanel)"
pg "${new_pw}" e2e_bob.bob e2e_bob 'drop table big' >/dev/null

# a dump that needs an extension tenants may not create fails in all-or-nothing mode
superuser "create database e2e_extsrc" >/dev/null
superuser "create extension file_fdw; create table t(i int); insert into t values (1)" e2e_extsrc >/dev/null
docker exec "${app}" gosu postgres pg_dump -h /var/lib/postgresql/run --format=custom e2e_extsrc > "${work}/files/ext.dump"
chmod a+r "${work}/files/ext.dump"
superuser "drop database e2e_extsrc" >/dev/null
browser failedImport
failed_subject='PostgreSQL: import of e2e_bob failed'
wait_mail bob@example.test 'create extension "file_fdw"' && pass "owner mailed the error of the failed import" || fail "owner mailed the error of the failed import" "$(mail_text bob@example.test | tail -20)"
wait_mail dba@example.test 'create extension "file_fdw"' && pass "admin address mailed the error of the failed import" || fail "admin address mailed the error of the failed import" "$(ls "${work}/mail")"
expect "failure mail subject" "^[1-9]" "$(mails bob@example.test "${failed_subject}")"
expect "group owner mailed" "^[1-9]" "$(mails carol@example.test "${failed_subject}")"
expect "non-owner not mailed" "^0$" "$(mails eve@example.test 'PostgreSQL: import')"
for _ in $(seq 1 10); do
    [[ "$(superuser "select count(*) from jobs where status = 'failed' and not notified" pgpanel)" == "0" ]] && break
    sleep 1
done
expect "failed jobs marked notified" "^0$" "$(superuser "select count(*) from jobs where status = 'failed' and not notified" pgpanel)"
failure_mails=$(ls "${work}/mail" | wc -l)
expect "failed import left the data unchanged" "^from dump$" "$(pg "${new_pw}" e2e_bob.bob e2e_bob 'select v from imported_marker')"
expect "failed import left no staging database" "^0$" "$(superuser "select count(*) from pg_database where datname like 'pgpanel\_%'")"
expect "import loaded the dump" "^from dump$" "$(pg "${new_pw}" e2e_bob.bob e2e_bob 'select v from imported_marker')"
expect "imported objects owned by bob" "^e2e_bob$" "$(pg "${new_pw}" e2e_bob.bob e2e_bob "select tableowner from pg_tables where tablename = 'imported_marker'")"
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
perms=$(docker exec "${app}" find /var/lib/postgresql/snapshots -mindepth 1 -printf '%y %m %g %p\n')
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
pg "${new_pw}" e2e_bob.bob e2e_bob 'insert into t values (1000)' >/dev/null
docker stop "${app}" >/dev/null
docker run --rm --read-only --tmpfs /tmp --tmpfs /run -v pge2e-data:/app/data -v pge2e-pg:/var/lib/postgresql \
    "${img}" /app/pkg/restore.sh >"${work}/restore.log" 2>&1 && pass "restore.sh" || fail "restore.sh" "$(tail -5 "${work}/restore.log")"
docker start "${app}" >/dev/null
wait_healthy
expect "data from backup" "^1,2,3$" "$(pg "${new_pw}" e2e_bob.bob e2e_bob "select string_agg(x::text, ',' order by x) from t")"
expect "allowlist survives restore" "${app_ip}" "$(docker exec "${app}" cat /run/pg/hba/pg_hba.conf)"

echo "==> Snapshot rows and files are reconciled"
gone_file=$(superuser "select file from snapshots where kind = 'pre_restore' order by id limit 1" pgpanel)
docker exec "${app}" rm "/var/lib/postgresql/snapshots/${gone_file}"
docker exec "${app}" bash -c 'cp "$(ls /var/lib/postgresql/snapshots/e2e_bob/*.dump | head -1)" /var/lib/postgresql/snapshots/e2e_bob/orphan.dump'
docker restart "${app}" >/dev/null
wait_healthy
sleep 3
expect "row of a missing snapshot file removed" "^0$" "$(superuser "select count(*) from snapshots where file = '${gone_file}'" pgpanel)"
expect "snapshot file without row removed" "^no$" "$(docker exec "${app}" bash -c 'test -e /var/lib/postgresql/snapshots/e2e_bob/orphan.dump && echo yes || echo no')"
browser afterRestore

expect "no failure mail repeated after restarts" "^${failure_mails}$" "$(ls "${work}/mail" | wc -l)"

echo "==> Logs"
expect "no panel or worker errors" "^$" "$(docker logs "${app}" 2>&1 | grep '"level":"ERROR"' | grep -v 'the file changed since it was uploaded\|file_fdw' || true)"
expect "no PostgreSQL errors except expected test failures" "^$" "$(docker logs "${app}" 2>&1 | grep -E ' (ERROR|PANIC):' | grep -vE 'permission denied (to create database|to create extension|to use|for)|must be superuser|role "postgres" already exists|COPY to or from an external program|file_fdw|current transaction is aborted' || true)"

echo
if [[ ${failures} -eq 0 ]]; then
    echo "==> All checks passed"
else
    echo "==> ${failures} failed"
    exit 1
fi
