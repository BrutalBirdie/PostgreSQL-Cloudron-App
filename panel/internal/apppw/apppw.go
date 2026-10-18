// Package apppw lets logins authenticate with a Cloudron app password.
// PostgreSQL runs "panel pam-auth" through pam_exec, which checks the password
// with the app bridge of the Cloudron box. The bridge only accepts app
// passwords created for this app.
// https://www.postgresql.org/docs/18/auth-pam.html
package apppw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"pgpanel/internal/hba"
)

// Map is written by the panel and read by the PAM helper, which runs as the
// postgres OS user without the app's environment.
type Map struct {
	Bridge string            `json:"bridge"` // CLOUDRON_APP_BRIDGE_ORIGIN
	Logins map[string]string `json:"logins"` // login role -> Cloudron username
}

func WriteMap(path string, m Map) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return hba.WriteFileAtomic(path, string(b)+"\n", 0o644)
}

func ReadMap(path string) (Map, error) {
	var m Map
	b, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	return m, json.Unmarshal(b, &m)
}

var ErrDenied = errors.New("app password not accepted")

// Verify checks password as an app password of the Cloudron user the login
// belongs to. Logins without an entry in the map are denied.
func Verify(ctx context.Context, m Map, client *http.Client, login, password string) error {
	username, ok := m.Logins[login]
	if !ok || username == "" {
		return fmt.Errorf("%w: %s does not use app passwords", ErrDenied, login)
	}
	if password == "" || m.Bridge == "" {
		return ErrDenied
	}
	body, _ := json.Marshal(map[string]string{"identifier": username, "password": password})
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(m.Bridge, "/")+"/verify-app-password", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized {
		return ErrDenied
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("app bridge: HTTP %d", res.StatusCode)
	}
	var user struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(res.Body).Decode(&user); err != nil {
		return err
	}
	if user.Username != username {
		return fmt.Errorf("%w: bridge answered for %q, login belongs to %q", ErrDenied, user.Username, username)
	}
	return nil
}

// ReadPassword reads the token pam_exec writes to stdin with expose_authtok,
// which ends with a NUL byte.
func ReadPassword(b []byte) string {
	s, _, _ := strings.Cut(string(b), "\x00")
	return strings.TrimRight(s, "\n")
}
