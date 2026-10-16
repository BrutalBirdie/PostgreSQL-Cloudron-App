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
	"strings"
	"syscall"
	"time"

	"pgpanel/internal/hba"
	"pgpanel/internal/store"
	"pgpanel/internal/web"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
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
		err = st.Migrate(ctx)
		if err == nil {
			break
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("migrate: %w", err)
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
		AdminGroup:    env("PG_ADMIN_GROUP", "postgres-admins"),
		Admins:        strings.FieldsFunc(os.Getenv("PG_ADMINS"), func(r rune) bool { return r == ',' || r == ' ' }),
		AllowlistFile: env("ALLOWLIST_FILE", "/app/data/allowed_networks.txt"),
		HBAFile:       env("HBA_FILE", "/run/pg/hba/pg_hba.conf"),
		PGAdminPath:   os.Getenv("PGADMIN_PATH"),
	}, st, log)
	if err != nil {
		return err
	}
	go srv.PurgeLoop(ctx)

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
