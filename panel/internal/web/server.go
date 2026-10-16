package web

import (
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/oauth2"

	"pgpanel/internal/access"
	"pgpanel/internal/directory"
	"pgpanel/internal/names"
	"pgpanel/internal/store"
)

//go:embed templates static
var assets embed.FS

const (
	sessionCookie = "__Host-session"
	stateCookie   = "__Host-oidc-state"
	idleTimeout   = 8 * time.Hour
	maxSession    = 24 * time.Hour
	maxBodyBytes  = 64 << 10
)

type Config struct {
	Origin        string // https://fqdn of the app
	PublicHost    string // host clients use to reach PostgreSQL
	PublicPort    string // empty when the TCP port is disabled
	Issuer        string
	ClientID      string
	ClientSecret  string
	Directory     *directory.Client // nil without the SCIM addon
	Admins        access.Admins
	AllowlistFile string
	HBAFile       string
	PGAdminPath   string // empty when pgAdmin is not bundled
	SnapshotDir   string
	UploadDir     string
	UploadKeep    time.Duration // uploads not marked keep are deleted after this
	PGBinDir      string
	MaxSnapshots  int
}

type Server struct {
	cfg   Config
	store *store.Store
	log   *slog.Logger
	pages map[string]*template.Template

	oidcMu   sync.Mutex
	provider *oidc.Provider

	hbaMu    sync.Mutex
	uploadMu sync.Mutex
	hashWake chan struct{}
}

func New(cfg Config, st *store.Store, log *slog.Logger) (*Server, error) {
	s := &Server{cfg: cfg, store: st, log: log, pages: map[string]*template.Template{}, hashWake: make(chan struct{}, 1)}
	funcs := template.FuncMap{"connURL": s.connURL, "bytes": humanBytes}
	for _, page := range []string{"login", "home", "admin", "secret", "audit", "error", "database", "restore", "uploads", "import", "role"} {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+page+".html")
		if err != nil {
			return nil, err
		}
		s.pages[page] = t
	}
	return s, nil
}

func (s *Server) Handler() http.Handler {
	static, _ := fs.Sub(assets, "static")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("GET /auth/callback", s.callback)

	mux.Handle("GET /{$}", s.requireLogin(s.home))
	mux.Handle("POST /logout", s.requireLogin(s.logout))
	mux.Handle("POST /roles/{name}/password", s.requireLogin(s.setMyPassword))
	mux.Handle("POST /roles/{name}/databases", s.requireLogin(s.createOwnDatabase))
	mux.Handle("POST /databases/{name}/delete", s.requireLogin(s.deleteDatabase))
	mux.Handle("GET /databases/{name}", s.requireLogin(s.databasePage))
	mux.Handle("POST /databases/{name}/snapshots", s.requireLogin(s.createSnapshot))
	mux.Handle("POST /databases/{name}/schedule", s.requireLogin(s.saveSchedule))
	mux.Handle("GET /snapshots/{id}/download", s.requireLogin(s.downloadSnapshot))
	mux.Handle("GET /snapshots/{id}/restore", s.requireLogin(s.restorePage))
	mux.Handle("POST /snapshots/{id}/restore", s.requireLogin(s.restoreSnapshot))
	mux.Handle("POST /snapshots/{id}/delete", s.requireLogin(s.deleteSnapshot))

	mux.Handle("GET /roles/{name}/uploads", s.requireLogin(s.uploadsPage))
	mux.Handle("POST /roles/{name}/uploads", s.requireLoginStream(s.uploadFile))
	mux.Handle("POST /uploads/{id}/keep", s.requireLogin(s.keepUpload))
	mux.Handle("POST /uploads/{id}/delete", s.requireLogin(s.deleteUpload))
	mux.Handle("POST /uploads/{id}/verify", s.requireLogin(s.verifyUpload))
	mux.Handle("GET /uploads/{id}/import", s.requireLogin(s.importPage))
	mux.Handle("POST /uploads/{id}/import", s.requireLogin(s.importUpload))

	mux.Handle("GET /admin", s.requireAdmin(s.admin))
	mux.Handle("GET /admin/audit", s.requireAdmin(s.auditLog))
	mux.Handle("POST /admin/allowlist", s.requireAdmin(s.saveAllowlist))
	mux.Handle("POST /admin/roles", s.requireAdmin(s.createRole))
	mux.Handle("GET /admin/principals", s.requireAdmin(s.principals))
	mux.Handle("GET /admin/roles/{name}", s.requireAdmin(s.rolePage))
	mux.Handle("POST /admin/roles/{name}/update", s.requireAdmin(s.updateRole))
	mux.Handle("POST /admin/roles/{name}/logins/{login}/revoke", s.requireAdmin(s.revokeLogin))
	mux.Handle("POST /admin/roles/{name}/delete", s.requireAdmin(s.deleteRole))
	mux.Handle("POST /admin/databases", s.requireAdmin(s.createDatabase))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// wasm-unsafe-eval lets the vendored hash-wasm compile its WebAssembly, eval stays blocked
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		// no-referrer would make browsers send "Origin: null" on form posts
		// https://fetch.spec.whatwg.org/#serializing-a-request-origin
		h.Set("Referrer-Policy", "same-origin")
		// pages can contain freshly generated passwords
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

type ctxKey struct{}

func sessionFrom(r *http.Request) *store.Session {
	sess, _ := r.Context().Value(ctxKey{}).(*store.Session)
	return sess
}

func (s *Server) requireLogin(h http.HandlerFunc) http.Handler { return s.authed(h, false) }

// requireLoginStream is for multipart uploads: the body is not parsed here and
// the handler must check the CSRF token itself with validCSRF.
func (s *Server) requireLoginStream(h http.HandlerFunc) http.Handler { return s.authed(h, true) }

func (s *Server) authed(h http.HandlerFunc, stream bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			s.render(w, r, http.StatusOK, "login", nil)
			return
		}
		sess, err := s.store.GetSession(r.Context(), c.Value, idleTimeout, maxSession)
		if errors.Is(err, store.ErrNotFound) {
			http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			s.render(w, r, http.StatusOK, "login", nil)
			return
		}
		if err != nil {
			s.internalError(w, r, err)
			return
		}
		member, ok := s.resolveMember(r.Context(), sess)
		if !ok {
			s.store.DeleteSession(r.Context(), c.Value)
			http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
			s.fail(w, r, http.StatusForbidden, "Your Cloudron account no longer has access to this app.")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, sess)
		r = r.WithContext(context.WithValue(ctx, memberKey{}, member))
		if r.Method == http.MethodPost && !(stream && s.validOrigin(r, sess) || !stream && s.validPost(w, r, sess)) {
			s.fail(w, r, http.StatusForbidden, "The request could not be verified. Reload the page and try again.")
			return
		}
		h(w, r)
	})
}

func (s *Server) requireAdmin(h http.HandlerFunc) http.Handler {
	return s.requireLogin(func(w http.ResponseWriter, r *http.Request) {
		if !sessionFrom(r).IsAdmin {
			s.fail(w, r, http.StatusForbidden, "Only admins can open this page. Admins are listed in PG_ADMINS or members of a group in PG_ADMIN_GROUP, both in /app/data/env.sh.")
			return
		}
		h(w, r)
	})
}

// validPost enforces same-origin and the per-session CSRF token on every state change.
func (s *Server) validPost(w http.ResponseWriter, r *http.Request, sess *store.Session) bool {
	if !s.validOrigin(r, sess) {
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		return s.rejectPost(r, sess, "invalid form: "+err.Error())
	}
	return s.validCSRF(r, sess, r.PostForm.Get("csrf"))
}

func (s *Server) validOrigin(r *http.Request, sess *store.Session) bool {
	if origin := r.Header.Get("Origin"); origin != "" && origin != s.cfg.Origin {
		return s.rejectPost(r, sess, "origin mismatch")
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return s.rejectPost(r, sess, "not same-origin")
	}
	return true
}

func (s *Server) validCSRF(r *http.Request, sess *store.Session, token string) bool {
	if subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRFToken)) != 1 {
		return s.rejectPost(r, sess, "csrf token mismatch")
	}
	return true
}

func (s *Server) rejectPost(r *http.Request, sess *store.Session, reason string) bool {
	s.log.Warn("post rejected", "path", r.URL.Path, "user", sess.Username, "reason", reason,
		"origin", r.Header.Get("Origin"), "sec_fetch_site", r.Header.Get("Sec-Fetch-Site"))
	return false
}

type pageData struct {
	Title       string
	Session     *store.Session
	PGAdminPath string
	Error       string
	Data        any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page string, data any) {
	s.renderMsg(w, r, status, page, "", data)
}

func (s *Server) renderMsg(w http.ResponseWriter, r *http.Request, status int, page, msg string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	err := s.pages[page].Execute(w, pageData{
		Title:       "PostgreSQL",
		Session:     sessionFrom(r),
		PGAdminPath: s.cfg.PGAdminPath,
		Error:       msg,
		Data:        data,
	})
	if err != nil {
		s.log.Error("render", "page", page, "err", err)
	}
}

func (s *Server) fail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.renderMsg(w, r, status, "error", msg, nil)
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("request failed", "path", r.URL.Path, "err", err)
	s.fail(w, r, http.StatusInternalServerError, "Internal error, see the app logs.")
}

// userError shows validation and PostgreSQL errors to the user, everything else is logged only.
func (s *Server) userError(w http.ResponseWriter, r *http.Request, err error) {
	var pgErr *pgconn.PgError
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.fail(w, r, http.StatusNotFound, "Not found.")
	case errors.Is(err, names.ErrInvalid), errors.Is(err, names.ErrReserved):
		s.fail(w, r, http.StatusBadRequest, "Invalid name: "+err.Error()+".")
	case errors.As(err, &pgErr):
		s.fail(w, r, http.StatusBadRequest, "PostgreSQL: "+pgErr.Message)
	case errors.Is(err, store.ErrJobActive):
		s.fail(w, r, http.StatusConflict, "Another snapshot or restore of this database is still running. Wait until it has finished.")
	case errors.Is(err, store.ErrLimitReached):
		s.fail(w, r, http.StatusBadRequest, "Limit reached: "+strings.TrimPrefix(err.Error(), store.ErrLimitReached.Error()+": ")+".")
	case errors.As(err, new(inputError)):
		s.fail(w, r, http.StatusBadRequest, err.Error())
	default:
		s.internalError(w, r, err)
	}
}

type inputError string

func (e inputError) Error() string { return string(e) }

func badInput(msg string) error { return inputError(msg) }

func (s *Server) audit(r *http.Request, action, target, detail string) {
	actor := sessionFrom(r).Username
	s.log.Info("audit", "actor", actor, "action", action, "target", target, "detail", detail)
	if err := s.store.Audit(r.Context(), store.AuditEntry{Actor: actor, Action: action, Target: target, Detail: detail}); err != nil {
		s.log.Error("audit write failed", "err", err)
	}
}

func (s *Server) connURL(role, db string) string {
	if s.cfg.PublicPort == "" {
		return ""
	}
	u := url.URL{
		Scheme:   "postgresql",
		User:     url.User(role),
		Host:     s.cfg.PublicHost + ":" + s.cfg.PublicPort,
		Path:     "/" + db,
		RawQuery: "sslmode=verify-full&sslrootcert=system",
	}
	return u.String()
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ok\n"))
}

// resolveMember looks the session user up in the directory. Group membership
// and admin rights follow Cloudron within the directory cache time. When the
// directory is down, the groups seen at login are kept; a user the directory
// no longer knows has lost access to the app.
func (s *Server) resolveMember(ctx context.Context, sess *store.Session) (access.Member, bool) {
	m := access.Member{Username: sess.Username}
	user, err := s.cfg.Directory.Lookup(ctx, sess.Username)
	switch {
	case errors.Is(err, directory.ErrNotConfigured):
		sess.IsAdmin = sess.IsAdmin || s.cfg.Admins.IsAdmin(m)
	case err != nil:
		s.log.Warn("directory lookup failed, using the groups from login", "user", sess.Username, "err", err)
		if user != nil {
			m = user.Member()
		}
		sess.IsAdmin = sess.IsAdmin || s.cfg.Admins.IsAdmin(m)
	case user == nil:
		return m, false
	default:
		m = user.Member()
		sess.IsAdmin = s.cfg.Admins.IsAdmin(m)
	}
	return m, true
}

// PurgeLoop removes expired sessions, abandoned logins and expired uploads.
func (s *Server) PurgeLoop(ctx context.Context) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		if err := s.store.PurgeExpired(ctx, idleTimeout, maxSession); err != nil && ctx.Err() == nil {
			s.log.Error("purge sessions", "err", err)
		}
		s.purgeUploads(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Server) oauthConfig(ctx context.Context) (*oidc.Provider, *oauth2.Config, error) {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	if s.provider == nil {
		p, err := oidc.NewProvider(ctx, s.cfg.Issuer)
		if err != nil {
			return nil, nil, err
		}
		s.provider = p
	}
	return s.provider, &oauth2.Config{
		ClientID:     s.cfg.ClientID,
		ClientSecret: s.cfg.ClientSecret,
		Endpoint:     s.provider.Endpoint(),
		RedirectURL:  s.cfg.Origin + "/auth/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}, nil
}

func formInt(r *http.Request, key string, def, min, max int) (int, error) {
	v := r.PostForm.Get(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, badInput(key + " must be a number between " + strconv.Itoa(min) + " and " + strconv.Itoa(max) + ".")
	}
	return n, nil
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return strconv.FormatFloat(float64(n)/float64(div), 'f', 1, 64) + " " + string("KMGTPE"[exp]) + "iB"
}
