package scram

import (
	"strings"
	"testing"
)

// expected value computed independently with Python hashlib/hmac
func TestVerifierKnownValue(t *testing.T) {
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	got, err := verifier("pencil", salt, 4096)
	if err != nil {
		t.Fatal(err)
	}
	want := "SCRAM-SHA-256$4096:AAECAwQFBgcICQoLDA0ODw==$zHCdol2044/ZyWzPLi7oxApCkamKw9Z+E4U/QApd/5Y=:dd5peBOitVnLNFu7VmwP+HiDaaw4OUCv396eVCWhYiE="
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestVerifierHasNoQuote(t *testing.T) {
	v, err := Verifier("x")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(v, "'\\") {
		t.Fatalf("verifier contains a quote: %s", v)
	}
}

func TestPassword(t *testing.T) {
	p, err := Password()
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 32 || strings.Trim(p, alphabet) != "" {
		t.Fatalf("bad password %q", p)
	}
}
