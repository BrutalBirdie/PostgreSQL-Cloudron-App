package uploads

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidName(t *testing.T) {
	for _, ok := range []string{"a.dump", "prod-2026_10.dump", "X"} {
		if !ValidName(ok) {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", ".hidden", "..", "a..b", "a/b", "../x", "a b", "ä.dump", "-x", "_x"} {
		if ValidName(bad) {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"prod.dump":             "prod.dump",
		`C:\Users\me\prod.dump`: "prod.dump",
		"../../etc/passwd":      "passwd",
		"my dump (1).dump":      "my_dump__1_.dump",
		".hidden":               "hidden",
		"..":                    "upload.dump",
		"äöü.dump":              "dump",
	}
	for in, want := range cases {
		got := SanitizeName(in)
		if got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
		if !ValidName(got) {
			t.Errorf("%q: sanitized %q is not valid", in, got)
		}
	}
}

func TestFormat(t *testing.T) {
	dir := t.TempDir()
	tarHead := make([]byte, 512)
	copy(tarHead[257:], "ustar")
	cases := []struct {
		content []byte
		want    string
		err     bool
	}{
		{[]byte("PGDMP\x01\x10"), "custom", false},
		{tarHead, "tar", false},
		{[]byte("--\n-- PostgreSQL database dump\n"), "", true},
		{[]byte("\\! rm -rf /\n"), "", true},
		{[]byte{0x1f, 0x8b, 8, 0}, "", true},
		{[]byte("hello"), "", true},
	}
	for i, c := range cases {
		p := filepath.Join(dir, "f")
		os.WriteFile(p, c.content, 0o600)
		got, err := Format(p)
		if got != c.want || (err != nil) != c.err {
			t.Errorf("case %d: got %q, %v", i, got, err)
		}
	}
}

func TestScanAndPath(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "good.dump"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, ".partial"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, "bad name.dump"), []byte("x"), 0o600)
	os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	files, err := Scan(dir)
	if err != nil || len(files) != 1 || files[0].Name != "good.dump" {
		t.Fatalf("scan = %v %v", files, err)
	}
	if _, err := Path("/root", "role", "../x"); err == nil {
		t.Error("path traversal accepted")
	}
	if _, err := Path("/root", "..", "x.dump"); err == nil {
		t.Error("role traversal accepted")
	}
}

func TestNormalizeSHA256(t *testing.T) {
	const h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	for _, in := range []string{h, "  " + h + "  ", h + "  prod.dump", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"} {
		got, err := NormalizeSHA256(in)
		if err != nil || got != h {
			t.Errorf("%q: got %q %v", in, got, err)
		}
	}
	if got, err := NormalizeSHA256("  "); got != "" || err != nil {
		t.Errorf("empty input: %q %v", got, err)
	}
	for _, bad := range []string{"abc", h + "0", "g" + h[1:]} {
		if _, err := NormalizeSHA256(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestHashFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "empty")
	os.WriteFile(p, nil, 0o600)
	got, err := HashFile(p)
	if err != nil || got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("got %q %v", got, err)
	}
}
