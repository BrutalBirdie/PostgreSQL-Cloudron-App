package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"pgpanel/internal/store"
)

func TestFilePosition(t *testing.T) {
	p := filepath.Join(t.TempDir(), "archive")
	os.WriteFile(p, make([]byte, 1000), 0o600)
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Read(make([]byte, 300))
	pos, ok := filePosition(os.Getpid(), p)
	if !ok || pos != 300 {
		t.Fatalf("pos = %d %v, want 300", pos, ok)
	}
	if _, ok := filePosition(os.Getpid(), p+"-other"); ok {
		t.Fatal("found a file that is not open")
	}
}

func TestRestoreStep(t *testing.T) {
	cases := map[string]string{
		`pg_restore: processing data for table "public.t"`:  `Processing data for table "public.t"`,
		`pg_restore: creating INDEX "public.t_idx"`:         `Creating INDEX "public.t_idx"`,
		`pg_restore: error: could not execute query`:        "",
		`pg_restore: warning: errors ignored on restore: 1`: "",
		`pg_restore: detail: Command was: CREATE EXTENSION`: "",
		`Command was: CREATE EXTENSION postgis;`:            "",
	}
	for in, want := range cases {
		if got := restoreStep(in); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestReporterThrottles(t *testing.T) {
	var calls []string
	ctx := withReporter(context.Background(), func(pct int, step string) { calls = append(calls, step) })
	report(ctx, 1, "a")
	report(ctx, 2, "a")
	report(ctx, 3, "b")
	if len(calls) != 2 || calls[1] != "b" {
		t.Fatalf("calls = %v", calls)
	}
	report(context.Background(), 1, "no reporter")
}

func TestHashWithProgress(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("hello"), 0o600)
	h := sha256.New()
	if err := hashWithProgress(context.Background(), p, h); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Fatalf("got %s", got)
	}
}

func TestDumpEstimate(t *testing.T) {
	e := newDumpEstimate(map[uint32]store.TableSize{
		1: {Name: "public.small", Bytes: 100, EstRows: 10},
		2: {Name: "public.big", Bytes: 900, EstRows: 90},
		3: {Name: "public.new", Bytes: 0, EstRows: -1},
	})
	steps := []struct {
		cp    *store.CopyProgress
		pct   int
		table string
	}{
		{nil, 0, ""},
		{&store.CopyProgress{Relid: 1, Tuples: 5}, 5, "public.small"},
		{&store.CopyProgress{Relid: 2, Tuples: 45}, 55, "public.big"},
		{&store.CopyProgress{Relid: 2, Tuples: 900}, 99, "public.big"}, // stale reltuples, capped
		{nil, 99, ""}, // between tables, never backwards
		{&store.CopyProgress{Relid: 3, Bytes: 50}, 99, "public.new"},
	}
	for i, s := range steps {
		pct, table := e.update(s.cp)
		if pct != s.pct || table != s.table {
			t.Errorf("step %d: got %d %q want %d %q", i, pct, table, s.pct, s.table)
		}
	}
	if pct, _ := newDumpEstimate(nil).update(nil); pct != -1 {
		t.Errorf("no sizes: got %d want -1", pct)
	}
}
