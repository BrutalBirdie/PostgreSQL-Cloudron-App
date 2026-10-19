package tuning

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	const mem = 2048
	cases := []struct {
		name, in, want string
		ok             bool
	}{
		{"max_connections", "150", "150", true},
		{"max_connections", "19", "", false},
		{"max_connections", "1e3", "", false},
		{"work_mem", "8MB", "8MB", true},
		{"work_mem", "8 mb", "8MB", true},
		{"work_mem", "64kB", "64kB", true},
		{"work_mem", "32kB", "", false},
		{"work_mem", "1GB", "", false},
		{"work_mem", "512MB", "512MB", true},
		{"shared_buffers", "1536MB", "1536MB", true},
		{"shared_buffers", "1537MB", "", false},
		{"statement_timeout", "0", "0", true},
		{"statement_timeout", "30s", "30s", true},
		{"statement_timeout", "25h", "", false},
		{"statement_timeout", "30S", "", false},
		{"work_mem", "8MB'\narchive_command = 'x", "", false},
		{"work_mem", "", "", false},
	}
	for _, c := range cases {
		p, _ := Lookup(c.name)
		got, err := p.Normalize(c.in, mem)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("%s %q: got %q, %v", c.name, c.in, got, err)
		}
	}
}

func TestValidateRejectsUnknown(t *testing.T) {
	out, errs := Validate(map[string]string{"archive_command": "sh", "work_mem": "8MB", "statement_timeout": " "}, 2048)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "archive_command") {
		t.Fatalf("errs = %v", errs)
	}
	if len(out) != 1 || out["work_mem"] != "8MB" {
		t.Fatalf("out = %v", out)
	}
}

func TestRender(t *testing.T) {
	got := Render(map[string]string{"work_mem": "8MB", "max_connections": "150"})
	if !strings.Contains(got, "max_connections = '150'\nwork_mem = '8MB'\n") {
		t.Fatalf("render = %q", got)
	}
}
