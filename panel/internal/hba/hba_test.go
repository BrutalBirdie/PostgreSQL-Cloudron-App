package hba

import (
	"strings"
	"testing"
)

func TestParseEntry(t *testing.T) {
	cases := map[string]string{
		"203.0.113.10":         "203.0.113.10/32",
		" 198.51.100.7/24 ":    "198.51.100.0/24",
		"2001:db8::1":          "2001:db8::1/128",
		"2001:db8::/48":        "2001:db8::/48",
		"::ffff:192.0.2.1":     "192.0.2.1/32",
		"::ffff:192.0.2.0/120": "192.0.2.0/24",
	}
	for in, want := range cases {
		p, err := ParseEntry(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if p.String() != want {
			t.Errorf("%q: got %s want %s", in, p, want)
		}
	}
	for _, in := range []string{"", "host", "1.2.3", "1.2.3.4/33", "fe80::1%eth0", "1.2.3.4 all", "1.2.3.4\nhost all all 0.0.0.0/0 trust"} {
		if _, err := ParseEntry(in); err == nil {
			t.Errorf("%q: expected error", in)
		}
	}
}

func TestParseFile(t *testing.T) {
	in := "# comment\n203.0.113.10 # server\n\nbad entry\n203.0.113.10/32\n2001:db8::/48\n"
	list, errs := Parse(strings.NewReader(in))
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "line 4") {
		t.Fatalf("errs = %v", errs)
	}
	if len(list) != 2 || list[0].String() != "203.0.113.10/32" || list[1].String() != "2001:db8::/48" {
		t.Fatalf("list = %v", list)
	}
	again, errs := Parse(strings.NewReader(FormatAllowlist(list)))
	if len(errs) != 0 || len(again) != 2 {
		t.Fatalf("round trip failed: %v %v", again, errs)
	}
}

func TestRender(t *testing.T) {
	list, _ := Parse(strings.NewReader("203.0.113.10\n"))
	out := Render(list, false)
	if !strings.Contains(out, "hostssl  all      +tenants          203.0.113.10/32  scram-sha-256") {
		t.Fatal(out)
	}
	pam := strings.Index(out, "hostssl  all      +apppw            203.0.113.10/32  pam pamservice=pgpanel")
	if pam < 0 || pam > strings.Index(out, "+tenants          203.0.113.10/32") {
		t.Fatal("app password rule must come before the SCRAM rule:\n" + out)
	}
	if strings.Contains(out, "host     all      +apppw") {
		t.Fatal("app passwords must not be accepted without TLS from remote")
	}
	if !strings.Contains(out, "local    all      +tenants          peer map=worker") {
		t.Fatal("worker rule missing")
	}
	if strings.Contains(out, "127.0.0.1") || strings.Contains(out, "trust") {
		t.Fatal(out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if !strings.HasSuffix(lines[len(lines)-1], "::/0       reject") {
		t.Fatal("last rule must reject everything")
	}
	if !strings.Contains(Render(nil, true), "127.0.0.1/32  scram-sha-256") {
		t.Fatal("localhost rule missing")
	}
}
