package worker

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"pgpanel/internal/store"
)

func TestResolve(t *testing.T) {
	ok := map[string]string{"db/1.dump": "/snap/db/1.dump", "db/../db/2.dump": "/snap/db/2.dump"}
	for in, want := range ok {
		got, err := Resolve("/snap", in)
		if err != nil || got != want {
			t.Errorf("%q: got %q %v want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"../etc/passwd", "db/../../etc/passwd", "/etc/passwd", ".."} {
		if _, err := Resolve("/snap", in); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}

func TestEnsureSharedDir(t *testing.T) {
	old := syscall.Umask(0o007)
	defer syscall.Umask(old)

	parent := t.TempDir()
	if err := os.Chmod(parent, os.ModeSetgid|0o770); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "db")
	if err := ensureSharedDir(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetgid == 0 || info.Mode().Perm() != 0o770 {
		t.Fatalf("mode = %v, want setgid and 0770", info.Mode())
	}

	plain := t.TempDir()
	if err := ensureSharedDir(filepath.Join(plain, "db")); err == nil {
		t.Fatal("a parent without setgid must be reported")
	}
}

func TestFailureMail(t *testing.T) {
	started := time.Date(2026, 10, 18, 13, 0, 0, 0, time.UTC)
	subject, body := failureMail(store.Job{Kind: "snapshot", Database: "app_one", Scheduled: true, RequestedBy: "schedule", Error: "pg_dump: disk full", StartedAt: &started}, "https://pg.example/")
	if subject != "PostgreSQL: scheduled snapshot of app_one failed" {
		t.Errorf("subject %q", subject)
	}
	for _, want := range []string{"2026-10-18 13:00 UTC", "pg_dump: disk full", "https://pg.example/databases/app_one"} {
		if !strings.Contains(body, want) {
			t.Errorf("body misses %q:\n%s", want, body)
		}
	}
}
