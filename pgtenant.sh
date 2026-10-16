#!/bin/bash

set -eu

source /app/pkg/common.sh

usage() {
    echo "Usage: $0 create <name>            create role <name> and database <name> owned by it"
    echo "       $0 login <role> <username>  create or rotate the login of a Cloudron user for a role"
    echo "       $0 list                     list roles, their databases and logins"
    echo "Owners are managed in the admin panel."
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
    local login="$1" password="$2" db="$3"
    local host="${CLOUDRON_APP_DOMAIN:-<app domain>}" port="${POSTGRES_PORT:-5432}"
    echo
    echo "Login:    ${login}"
    echo "Password: ${password}"
    echo "URL:      postgresql://${login}:${password}@${host}:${port}/${db}?sslmode=verify-full&sslrootcert=system"
    echo
    echo "The password is not stored anywhere. Save it now."
}

[[ $# -ge 1 ]] || usage

case "$1" in
create)
    [[ $# -eq 2 ]] || usage
    validate_name "$2"
    psql_admin -q -d postgres -v name="$2" <<'EOF'
CREATE ROLE :"name" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20 IN ROLE tenants PASSWORD NULL;
CREATE DATABASE :"name" OWNER :"name";
REVOKE ALL ON DATABASE :"name" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"name" TO :"name";
EOF
    pg_grant_tenants_to_panel
    echo "Created role and database $2. Add owners in the admin panel, they create their own logins there."
    ;;
login)
    [[ $# -eq 3 ]] || usage
    validate_name "$2"
    if [[ ! "$3" =~ ^[a-z0-9][a-z0-9._-]*$ ]] || (( ${#2} + ${#3} > 62 )); then
        echo "Invalid username '$3', or role and username are too long together" >&2
        exit 1
    fi
    login="$2.$3"
    password=$(random_password)
    exists=$(psql_admin -At -d postgres -v login="${login}" <<< "SELECT count(*) FROM pg_roles WHERE rolname = :'login'")
    if [[ "${exists}" == "1" ]]; then
        psql_admin -q -d postgres -v login="${login}" -v verifier="$(scram_verifier "${password}")" <<< "ALTER ROLE :\"login\" PASSWORD :'verifier';"
        psql_admin -q -d pgpanel -v login="${login}" <<< "UPDATE role_logins SET rotated_at = now() WHERE login_role = :'login';"
    else
        psql_admin -q -d postgres -v login="${login}" -v role="$2" -v verifier="$(scram_verifier "${password}")" <<'EOF'
CREATE ROLE :"login" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 20 IN ROLE :"role" PASSWORD :'verifier';
ALTER ROLE :"login" SET role = :'role';
GRANT :"login" TO pgpanel WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
EOF
        psql_admin -q -d pgpanel -v login="${login}" -v role="$2" -v username="$3" <<< "INSERT INTO role_logins (login_role, role_name, username) VALUES (:'login', :'role', :'username');"
    fi
    print_connection "${login}" "${password}" "$2"
    echo "The login is removed automatically when $3 is not an owner of $2."
    ;;
list)
    psql_admin -d postgres -c "SELECT r.rolname AS role, r.rolconnlimit AS conn_limit, string_agg(d.datname, ', ' ORDER BY d.datname) AS databases
        FROM pg_roles r JOIN pg_auth_members m ON m.member = r.oid JOIN pg_roles g ON g.oid = m.roleid AND g.rolname = 'tenants'
        LEFT JOIN pg_database d ON d.datdba = r.oid WHERE r.rolname <> 'pgpanel' GROUP BY r.rolname, r.rolconnlimit ORDER BY r.rolname"
    psql_admin -d pgpanel -c "SELECT login_role AS login, role_name AS role, username, rotated_at FROM role_logins ORDER BY role_name, username"
    ;;
*)
    usage
    ;;
esac
