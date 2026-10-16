#!/bin/bash

set -eu

source /app/pkg/common.sh

usage() {
    echo "Usage: $0 create <name>   create login role <name> and database <name> owned by it"
    echo "       $0 passwd <name>   set a new random password for role <name>"
    echo "       $0 list            list tenant roles and their databases"
    exit 1
}

validate_name() {
    if [[ ! "$1" =~ ^[a-z][a-z0-9_]{2,62}$ || "$1" =~ ^pg_ || " postgres pgpanel tenants template0 template1 public " == *" $1 "* ]]; then
        echo "Invalid name '$1': use 3-63 chars of a-z, 0-9, _ starting with a letter; pg_* and built-in names are reserved" >&2
        exit 1
    fi
}

random_password() {
    openssl rand -base64 64 | tr -dc 'A-Za-z0-9' | head -c 32
}

# SCRAM verifier is computed here so the plaintext password never reaches the server
# https://www.postgresql.org/docs/18/sasl-authentication.html#SASL-SCRAM-SHA-256
scram_verifier() {
    local password="$1" iterations=4096 salt salted_hex stored_key server_key
    # an ASCII salt keeps everything in shell variables, 32 hex chars carry 128 bits
    salt=$(openssl rand -hex 16)
    salted_hex=$(openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt pass:"${password}" -kdfopt salt:"${salt}" -kdfopt iter:${iterations} -binary PBKDF2 | od -An -tx1 | tr -d ' \n')
    stored_key=$(printf 'Client Key' | openssl mac -digest SHA256 -macopt hexkey:"${salted_hex}" -binary HMAC | openssl dgst -sha256 -binary | base64 -w0)
    server_key=$(printf 'Server Key' | openssl mac -digest SHA256 -macopt hexkey:"${salted_hex}" -binary HMAC | base64 -w0)
    printf 'SCRAM-SHA-256$%s:%s$%s:%s' "${iterations}" "$(printf '%s' "${salt}" | base64 -w0)" "${stored_key}" "${server_key}"
}

print_connection() {
    local name="$1" password="$2"
    local host="${CLOUDRON_APP_DOMAIN:-<app domain>}" port="${POSTGRES_PORT:-5432}"
    echo
    echo "Role:     ${name}"
    echo "Password: ${password}"
    echo "URL:      postgresql://${name}:${password}@${host}:${port}/${name}?sslmode=verify-full&sslrootcert=system"
    echo
    echo "The password is not stored anywhere. Save it now."
}

[[ $# -ge 1 ]] || usage

case "$1" in
create)
    [[ $# -eq 2 ]] || usage
    validate_name "$2"
    password=$(random_password)
    psql_admin -q -d postgres -v name="$2" -v verifier="$(scram_verifier "${password}")" <<'EOF'
CREATE ROLE :"name" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20 IN ROLE tenants PASSWORD :'verifier';
CREATE DATABASE :"name" OWNER :"name";
REVOKE ALL ON DATABASE :"name" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"name" TO :"name";
EOF
    pg_grant_tenants_to_panel
    print_connection "$2" "${password}"
    ;;
passwd)
    [[ $# -eq 2 ]] || usage
    validate_name "$2"
    is_tenant=$(psql_admin -At -d postgres -v name="$2" <<< "SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member JOIN pg_roles g ON g.oid = m.roleid WHERE r.rolname = :'name' AND r.rolname <> 'pgpanel' AND g.rolname = 'tenants'")
    [[ "${is_tenant}" == "1" ]] || { echo "Role '$2' is not a tenant role" >&2; exit 1; }
    password=$(random_password)
    psql_admin -q -d postgres -v name="$2" -v verifier="$(scram_verifier "${password}")" <<'EOF'
ALTER ROLE :"name" PASSWORD :'verifier';
EOF
    print_connection "$2" "${password}"
    ;;
list)
    psql_admin -d postgres -c "SELECT r.rolname AS role, r.rolconnlimit AS conn_limit, string_agg(d.datname, ', ' ORDER BY d.datname) AS databases
        FROM pg_roles r JOIN pg_auth_members m ON m.member = r.oid JOIN pg_roles g ON g.oid = m.roleid AND g.rolname = 'tenants'
        LEFT JOIN pg_database d ON d.datdba = r.oid WHERE r.rolname <> 'pgpanel' GROUP BY r.rolname, r.rolconnlimit ORDER BY r.rolname"
    ;;
*)
    usage
    ;;
esac
