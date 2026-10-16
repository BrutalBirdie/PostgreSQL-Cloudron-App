package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"pgpanel/internal/access"
	"pgpanel/internal/directory"
	"pgpanel/internal/hba"
	"pgpanel/internal/store"
	"pgpanel/internal/web"
	"pgpanel/internal/worker"
)

var (
	snapshotDir = env("SNAPSHOT_DIR", "/var/lib/postgresql/snapshots")
	uploadDir   = env("UPLOAD_DIR", "/app/data/uploads")
	pgBinDir    = env("PG_BIN_DIR", "/usr/lib/postgresql/18/bin")
	socketDir   = env("PG_SOCKET_DIR", "/var/lib/postgresql/run")
)

func uploadRetention() time.Duration {
	n, err := strconv.Atoi(os.Getenv("PG_UPLOAD_RETENTION_DAYS"))
	if err != nil || n < 1 {
		n = 8
	}
	return time.Duration(n) * 24 * time.Hour
}

func scimClient() *directory.Client {
	ttl, err := time.ParseDuration(os.Getenv("PANEL_SCIM_CACHE"))
	if err != nil || ttl <= 0 {
		ttl = 2 * time.Minute
	}
	return directory.New(os.Getenv("CLOUDRON_SCIM_ORIGIN"), os.Getenv("CLOUDRON_SCIM_TOKEN"), ttl)
}

func accessSyncInterval() time.Duration {
	d, err := time.ParseDuration(os.Getenv("PANEL_ACCESS_SYNC"))
	if err != nil || d <= 0 {
		return time.Minute
	}
	return d
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
}

func admins() access.Admins {
	return access.Admins{Users: splitList(os.Getenv("PG_ADMINS")), Groups: splitList(env("PG_ADMIN_GROUP", "postgres-admins"))}
}

func maxSnapshots() int {
	n, err := strconv.Atoi(os.Getenv("PG_MAX_SNAPSHOTS"))
	if err != nil || n < 1 {
		return 7
	}
	return n
}

// runWorker runs as the postgres OS user, see package worker.
func runWorker(log *slog.Logger) error {
	// snapshot files and directories must be usable by the panel's group
	syscall.Umask(0o007)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	st, err := store.Open(ctx, env("WORKER_DATABASE_URL", "host="+socketDir+" user=postgres dbname=pgpanel"))
	if err != nil {
		return err
	}
	defer st.Close()
	// the panel owns and creates the tables, a table created by the superuser would lock it out
	for deadline := time.Now().Add(120 * time.Second); ; {
		err = st.SchemaReady(ctx)
		if err == nil {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return err
		}
		time.Sleep(2 * time.Second)
	}
	w := worker.New(worker.Config{Directory: scimClient(), Admins: admins(), SnapshotDir: snapshotDir, UploadDir: uploadDir, SocketDir: socketDir, BinDir: pgBinDir, MaxSnapshots: maxSnapshots()}, st, log)
	go w.AccessSync(ctx, accessSyncInterval())
	return w.Run(ctx)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if len(os.Args) > 1 && os.Args[1] == "worker" {
		if err := runWorker(log); err != nil {
			log.Error("worker stopped", "err", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "render-hba" {
		if err := renderHBA(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "render-hba:", err)
			os.Exit(1)
		}
		return
	}
	if err := serve(log); err != nil {
		log.Error("panel stopped", "err", err)
		os.Exit(1)
	}
}

// renderHBA is called by start.sh, so the allowlist is parsed by the same code as in the panel.
func renderHBA(args []string) error {
	fs := flag.NewFlagSet("render-hba", flag.ExitOnError)
	allowlist := fs.String("allowlist", "/app/data/allowed_networks.txt", "allowlist file")
	out := fs.String("out", "/run/pg/hba/pg_hba.conf", "pg_hba.conf to write")
	localhost := fs.Bool("localhost", false, "allow tenant logins from 127.0.0.1 (pgAdmin)")
	fs.Parse(args)

	list, errs := hba.ReadFile(*allowlist)
	for _, err := range errs {
		fmt.Fprintln(os.Stderr, "==> Ignoring invalid allowlist entry:", err)
	}
	for _, p := range list {
		fmt.Fprintln(os.Stderr, "==> Allowing", p)
		if p.Bits() == 0 {
			fmt.Fprintln(os.Stderr, "==> WARNING:", p, "opens PostgreSQL to the whole internet")
		}
	}
	return hba.WriteFileAtomic(*out, hba.Render(list, *localhost), 0o644)
}

func serve(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	origin := os.Getenv("CLOUDRON_APP_ORIGIN")
	if origin == "" {
		return errors.New("CLOUDRON_APP_ORIGIN is not set")
	}
	if os.Getenv("CLOUDRON_OIDC_ISSUER") == "" {
		return errors.New("CLOUDRON_OIDC_ISSUER is not set, the oidc addon is required")
	}

	st, err := store.Open(ctx, env("PANEL_DATABASE_URL", "host=/var/lib/postgresql/run user=pgpanel dbname=pgpanel"))
	if err != nil {
		return err
	}
	defer st.Close()
	// supervisor starts PostgreSQL and the panel at the same time
	for deadline := time.Now().Add(60 * time.Second); ; {
		err = st.CreateSchema(ctx)
		if err == nil {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("creating the schema: %w", err)
		}
		log.Info("waiting for postgresql", "err", err)
		time.Sleep(2 * time.Second)
	}

	srv, err := web.New(web.Config{
		Origin:        origin,
		PublicHost:    os.Getenv("CLOUDRON_APP_DOMAIN"),
		PublicPort:    os.Getenv("POSTGRES_PORT"),
		Issuer:        os.Getenv("CLOUDRON_OIDC_ISSUER"),
		ClientID:      os.Getenv("CLOUDRON_OIDC_CLIENT_ID"),
		ClientSecret:  os.Getenv("CLOUDRON_OIDC_CLIENT_SECRET"),
		Directory:     scimClient(),
		Admins:        admins(),
		AllowlistFile: env("ALLOWLIST_FILE", "/app/data/allowed_networks.txt"),
		HBAFile:       env("HBA_FILE", "/run/pg/hba/pg_hba.conf"),
		PGAdminPath:   os.Getenv("PGADMIN_PATH"),
		SnapshotDir:   snapshotDir,
		UploadDir:     uploadDir,
		UploadKeep:    uploadRetention(),
		PGBinDir:      pgBinDir,
		MaxSnapshots:  maxSnapshots(),
	}, st, log)
	if err != nil {
		return err
	}
	go srv.PurgeLoop(ctx)
	go srv.HashLoop(ctx)

	httpServer := &http.Server{
		Addr:              env("PANEL_LISTEN", "127.0.0.1:3000"),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpServer.Shutdown(shutdownCtx)
	}()
	log.Info("panel listening", "addr", httpServer.Addr)
	if err := httpServer.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
