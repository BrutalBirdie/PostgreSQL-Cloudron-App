Remote connections are blocked until you allow a network.

1. Add your client's IP or network to `/app/data/allowed_networks.txt` (File Manager or Web Terminal) and restart the app.
2. In the Web Terminal, create a role and a database with the same name:
   `/app/pkg/pgtenant.sh create myapp`
   The password is printed once and not stored.
3. Connect with TLS verification:
   `psql "postgresql://myapp:<password>@$CLOUDRON-APP-FQDN:<port>/myapp?sslmode=verify-full&sslrootcert=system"`
