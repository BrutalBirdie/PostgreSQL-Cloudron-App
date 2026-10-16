## About

A standalone PostgreSQL 18 server for clients outside of Cloudron.

* Connections are TLS 1.3 only, using the app domain's certificate
* Passwords use SCRAM-SHA-256
* Remote access is blocked until a network is added to the allowlist
* Each role only gets access to its own database
* Backups are logical dumps taken by Cloudron's backup
