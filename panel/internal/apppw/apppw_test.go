package apppw

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// bridge mimics POST /verify-app-password of the box app bridge.
func bridge(t *testing.T, answerAs string) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Identifier, Password string }
		if r.Method != http.MethodPost || r.URL.Path != "/verify-app-password" || json.NewDecoder(r.Body).Decode(&in) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if in.Identifier != "bob" || in.Password != "app-secret" {
			http.Error(w, `{"message":"Password is not valid"}`, http.StatusUnauthorized)
			return
		}
		name := in.Identifier
		if answerAs != "" {
			name = answerAs
		}
		json.NewEncoder(w).Encode(map[string]string{"id": "uid-1", "username": name})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVerify(t *testing.T) {
	srv := bridge(t, "")
	m := Map{Bridge: srv.URL + "/", Logins: map[string]string{"app_one.bob": "bob"}}
	ctx := context.Background()
	if err := Verify(ctx, m, srv.Client(), "app_one.bob", "app-secret"); err != nil {
		t.Fatalf("valid app password: %v", err)
	}
	for name, c := range map[string]struct{ login, password string }{
		"wrong password":   {"app_one.bob", "nope"},
		"empty password":   {"app_one.bob", ""},
		"login not mapped": {"app_one.carol", "app-secret"},
		"shared role":      {"app_one", "app-secret"},
	} {
		if err := Verify(ctx, m, srv.Client(), c.login, c.password); !errors.Is(err, ErrDenied) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestVerifyOtherUser(t *testing.T) {
	srv := bridge(t, "mallory")
	m := Map{Bridge: srv.URL, Logins: map[string]string{"app_one.bob": "bob"}}
	if err := Verify(context.Background(), m, srv.Client(), "app_one.bob", "app-secret"); !errors.Is(err, ErrDenied) {
		t.Fatalf("answer for another user accepted: %v", err)
	}
}

func TestVerifyBridgeDown(t *testing.T) {
	srv := bridge(t, "")
	srv.Close()
	m := Map{Bridge: srv.URL, Logins: map[string]string{"app_one.bob": "bob"}}
	if err := Verify(context.Background(), m, http.DefaultClient, "app_one.bob", "app-secret"); err == nil {
		t.Fatal("unreachable bridge accepted")
	}
}

func TestMapRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "apppw.json")
	want := Map{Bridge: "http://172.18.0.1:3006", Logins: map[string]string{"app_one.bob": "bob"}}
	if err := WriteMap(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadMap(path)
	if err != nil || got.Bridge != want.Bridge || got.Logins["app_one.bob"] != "bob" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestReadPassword(t *testing.T) {
	for in, want := range map[string]string{"secret\x00": "secret", "secret": "secret", "secret\n": "secret", "": ""} {
		if got := ReadPassword([]byte(in)); got != want {
			t.Errorf("%q: got %q", in, got)
		}
	}
}
