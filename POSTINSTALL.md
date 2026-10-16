Remote connections are blocked until you allow a network.

1. Make yourself an admin: set `PG_ADMINS="<your username>"` in `/app/data/env.sh` and restart the app, or add yourself to a Cloudron group named `postgres-admins`.
2. Open the app, sign in, and go to **Admin**.
3. Add the IP address of your client server under **Allowed networks**.
4. Create a role. Its password is shown once and not stored.
5. Connect with TLS verification:
   `psql "postgresql://<role>:<password>@$CLOUDRON-APP-FQDN:<port>/<database>?sslmode=verify-full&sslrootcert=system"`
