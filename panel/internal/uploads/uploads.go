// Package uploads handles dump files in /app/data/uploads/<role>/. Files get
// there through the panel or the Cloudron File Manager. The directories are
// owned by cloudron (panel) with setgid group postgres, so the worker can read.
package uploads

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$`)

// ValidName rejects hidden files (in-progress uploads use a dot prefix) and
// anything that could be read as a path.
func ValidName(name string) bool {
	return namePattern.MatchString(name) && !strings.Contains(name, "..")
}

// SanitizeName turns a browser supplied file name into a valid one.
func SanitizeName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, `\`, "/"))
	var b strings.Builder
	for _, r := range name {
		if r < 128 && (r == '.' || r == '-' || r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	s := strings.TrimLeft(strings.ReplaceAll(b.String(), "..", "_"), "._-")
	if len(s) > 200 {
		s = s[len(s)-200:]
	}
	if s == "" {
		s = "upload.dump"
	}
	return s
}

type File struct {
	Name    string
	Size    int64
	ModTime time.Time
}

// Scan lists the valid regular files of a role's upload directory.
func Scan(dir string) ([]File, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var files []File
	for _, e := range entries {
		if !e.Type().IsRegular() || !ValidName(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, File{Name: e.Name(), Size: info.Size(), ModTime: info.ModTime()})
	}
	return files, nil
}

// Path returns the file path inside root/role, refusing anything else.
func Path(root, role, name string) (string, error) {
	if !ValidName(name) || !ValidName(role) {
		return "", fmt.Errorf("invalid upload name %q", name)
	}
	return filepath.Join(root, role, name), nil
}

var ErrPlainSQL = errors.New("plain SQL files cannot be imported on the server, because psql would execute meta-commands such as \\! from the file. Create the dump with pg_dump --format=custom, or import it remotely with psql")

// Format detects pg_dump archive formats by their magic bytes.
func Format(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	head := make([]byte, 512)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", err
	}
	head = head[:n]
	switch {
	case bytes.HasPrefix(head, []byte("PGDMP")):
		return "custom", nil
	case len(head) >= 262 && bytes.Equal(head[257:262], []byte("ustar")):
		return "tar", nil
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		return "", errors.New("gzip compressed files are not supported, upload the uncompressed pg_dump archive (custom format is compressed already)")
	case looksLikeSQL(head):
		return "", ErrPlainSQL
	}
	return "", errors.New("not a pg_dump archive, use pg_dump --format=custom or --format=tar")
}

func looksLikeSQL(head []byte) bool {
	s := strings.TrimSpace(string(head))
	for _, p := range []string{"--", "SET ", "CREATE ", "\\", "BEGIN", "SELECT ", "INSERT "} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
