Remote connections are blocked until you allow a network.

1. Make yourself an admin: set `PG_ADMINS="<your username>"` in `/app/data/env.sh` and restart the app. To make the members of Cloudron groups admins, list the groups in `PG_ADMIN_GROUP`, separated by commas.
2. Open the app, sign in, and go to **Admin**.
3. Add the IP address of your client server under **Admin > Network**.
4. Create a role under **Admin > Roles** and choose its owners (Cloudron users and groups).
5. Each owner signs in, opens the role settings (gear icon) on **My databases** and creates an own password. It is shown once and not stored.
6. Connect with TLS verification, using your login `<role>.<username>`:
   `psql "postgresql://<role>.<username>:<password>@$CLOUDRON-APP-FQDN:<port>/<database>?sslmode=verify-full&sslrootcert=system"`
   On Windows, `sslrootcert=system` does not find the Windows certificate store. Download [isrgrootx1.pem](https://letsencrypt.org/certs/isrgrootx1.pem) and pass its path instead.
