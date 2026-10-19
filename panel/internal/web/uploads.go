package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"pgpanel/internal/store"
	"pgpanel/internal/uploads"
)

// authorizeRole returns the role when the session may manage it.
func (s *Server) authorizeRole(r *http.Request, name string) (*store.Role, error) {
	role, err := s.store.GetRole(r.Context(), name)
	if err != nil {
		return nil, err
	}
	if !canManage(r, role) {
		return nil, store.ErrNotFound
	}
	return role, nil
}

func (s *Server) authorizeUpload(r *http.Request) (*store.Upload, *store.Role, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return nil, nil, store.ErrNotFound
	}
	up, err := s.store.GetUpload(r.Context(), id)
	if err != nil {
		return nil, nil, err
	}
	role, err := s.authorizeRole(r, up.RoleName)
	if err != nil {
		return nil, nil, err
	}
	return up, role, nil
}

func (s *Server) uploadDir(role string) string { return filepath.Join(s.cfg.UploadDir, role) }

// syncUploads registers files that were copied into the directory, for example
// with the Cloudron File Manager, and forgets files that are gone.
func (s *Server) syncUploads(ctx context.Context, role string) error {
	files, err := uploads.Scan(s.uploadDir(role))
	if err != nil {
		return err
	}
	states := make(map[string]store.FileState, len(files))
	for _, f := range files {
		states[f.Name] = store.FileState{Size: f.Size, MTime: f.ModTime}
	}
	if err := s.store.SyncUploads(ctx, role, states, "file manager"); err != nil {
		return err
	}
	s.wakeHasher()
	return nil
}

type uploadView struct {
	store.Upload
	Format    string
	FormatErr string
	Expires   time.Time
}

type uploadsData struct {
	Role     store.Role
	Roles    []string // role picker, the user's roles plus the shown one
	Uploads  []uploadView
	Dir      string
	KeepDays int
}

// uploadsStart opens the uploads of the user's first role.
func (s *Server) uploadsStart(w http.ResponseWriter, r *http.Request) {
	roles, err := s.store.RolesOwnedBy(r.Context(), memberFrom(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if len(roles) == 0 {
		s.render(w, r, http.StatusOK, "uploads", uploadsData{})
		return
	}
	http.Redirect(w, r, "/roles/"+roles[0].Name+"/uploads", http.StatusSeeOther)
}

func (s *Server) uploadsPage(w http.ResponseWriter, r *http.Request) {
	role, err := s.authorizeRole(r, r.PathValue("name"))
	if err != nil {
		s.userError(w, r, err)
		return
	}
	// created here so the File Manager shows the folder before anyone uploads
	if err := os.MkdirAll(s.uploadDir(role.Name), 0o750); err != nil {
		s.internalError(w, r, err)
		return
	}
	if err := s.syncUploads(r.Context(), role.Name); err != nil {
		s.internalError(w, r, err)
		return
	}
	list, err := s.store.ListUploads(r.Context(), role.Name)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	views := make([]uploadView, len(list))
	for i, up := range list {
		views[i] = s.viewUpload(up)
	}
	owned, err := s.store.RolesOwnedBy(r.Context(), memberFrom(r))
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	var picker []string
	for _, o := range owned {
		picker = append(picker, o.Name)
	}
	if !slices.Contains(picker, role.Name) {
		picker = append(picker, role.Name)
	}
	s.render(w, r, http.StatusOK, "uploads", uploadsData{Role: *role, Roles: picker, Uploads: views, Dir: s.uploadDir(role.Name), KeepDays: int(s.cfg.UploadKeep.Hours() / 24)})
}

func (s *Server) viewUpload(up store.Upload) uploadView {
	v := uploadView{Upload: up, Expires: up.FirstSeen.Add(s.cfg.UploadKeep)}
	path, err := uploads.Path(s.cfg.UploadDir, up.RoleName, up.FileName)
	if err == nil {
		v.Format, err = uploads.Format(path)
	}
	if err != nil {
		v.FormatErr = err.Error()
	}
	return v
}

// uploadFile streams a multipart upload to disk and hashes it on the way with
// io.MultiWriter. The CSRF token is the first part, so it is checked before any
// file data is written. Checksums come from the X-File-SHA256 header (computed
// by upload.js in the browser) and the optional sha256 form field (computed by
// the user where the dump was made). A mismatch discards the file.
func (s *Server) uploadFile(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	role, err := s.authorizeRole(r, r.PathValue("name"))
	if err != nil {
		s.uploadResult(w, r, "", err)
		return
	}
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Time{})
	rc.SetWriteDeadline(time.Time{})

	browserSum, err := uploads.NormalizeSHA256(r.Header.Get("X-File-SHA256"))
	if err != nil {
		s.uploadResult(w, r, "", badInput("Browser checksum: "+err.Error()+"."))
		return
	}
	mr, err := r.MultipartReader()
	if err != nil {
		s.uploadResult(w, r, "", badInput("Expected a file upload."))
		return
	}
	part, err := mr.NextPart()
	if err != nil || part.FormName() != "csrf" {
		s.uploadResult(w, r, "", errForbidden)
		return
	}
	token, _ := io.ReadAll(io.LimitReader(part, 256))
	if !s.validCSRF(r, sess, string(token)) {
		s.uploadResult(w, r, "", errForbidden)
		return
	}
	var userSum string
	for {
		part, err = mr.NextPart()
		if err != nil || part.FormName() == "file" {
			break
		}
		if part.FormName() == "sha256" {
			value, _ := io.ReadAll(io.LimitReader(part, 512))
			if userSum, err = uploads.NormalizeSHA256(string(value)); err != nil {
				s.uploadResult(w, r, "", badInput("Your checksum: "+err.Error()+"."))
				return
			}
		}
	}
	if err != nil || part.FileName() == "" {
		s.uploadResult(w, r, "", badInput("Choose a file to upload."))
		return
	}

	dir := s.uploadDir(role.Name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		s.uploadResult(w, r, "", err)
		return
	}
	suffix := make([]byte, 6)
	rand.Read(suffix)
	tmp := filepath.Join(dir, ".uploading-"+hex.EncodeToString(suffix))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		s.uploadResult(w, r, "", err)
		return
	}
	hasher := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(f, hasher), part)
	syncErr := f.Sync()
	closeErr := f.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		os.Remove(tmp)
		s.log.Warn("upload aborted", "role", role.Name, "err", errors.Join(copyErr, syncErr, closeErr))
		s.uploadResult(w, r, "", badInput("The upload was interrupted. Try again, or copy large files with the Cloudron File Manager."))
		return
	}
	sum := hex.EncodeToString(hasher.Sum(nil))
	for _, c := range []struct{ name, want string }{{"the checksum calculated by your browser", browserSum}, {"your checksum", userSum}} {
		if c.want != "" && c.want != sum {
			os.Remove(tmp)
			s.log.Warn("upload checksum mismatch", "role", role.Name, "expected", c.want, "got", sum)
			s.uploadResult(w, r, "", badInput(fmt.Sprintf("The file was not saved: its SHA-256 on the server is %s, %s is %s.", sum, c.name, c.want)))
			return
		}
	}
	verifiedBy := ""
	if userSum != "" {
		verifiedBy = "user"
	} else if browserSum != "" {
		verifiedBy = "browser"
	}

	name, err := s.placeUpload(tmp, dir, uploads.SanitizeName(part.FileName()))
	if err != nil {
		os.Remove(tmp)
		s.uploadResult(w, r, "", err)
		return
	}
	info, err := os.Stat(filepath.Join(dir, name))
	if err == nil {
		err = s.store.AddUpload(r.Context(), role.Name, name, store.FileState{Size: info.Size(), MTime: info.ModTime()}, sess.Username, sum, verifiedBy)
	}
	if err != nil {
		s.uploadResult(w, r, "", err)
		return
	}
	s.audit(r, "upload.create", role.Name, fmt.Sprintf("file=%s size=%d sha256=%s verified_by=%s", name, size, sum, verifiedBy))
	s.uploadResult(w, r, "/roles/"+role.Name+"/uploads", nil)
}

var errForbidden = errors.New("forbidden")

// uploadResult answers the JavaScript upload with JSON and the plain form with a page.
func (s *Server) uploadResult(w http.ResponseWriter, r *http.Request, next string, err error) {
	if !strings.Contains(r.Header.Get("Accept"), "application/json") {
		switch {
		case err == nil:
			http.Redirect(w, r, next, http.StatusSeeOther)
		case errors.Is(err, errForbidden):
			s.fail(w, r, http.StatusForbidden, "The request could not be verified. Reload the page and try again.")
		default:
			s.userError(w, r, err)
		}
		return
	}
	status, body := http.StatusOK, map[string]string{"redirect": next}
	var in inputError
	switch {
	case err == nil:
	case errors.Is(err, errForbidden):
		status, body = http.StatusForbidden, map[string]string{"error": "The request could not be verified. Reload the page and try again."}
	case errors.Is(err, store.ErrNotFound):
		status, body = http.StatusNotFound, map[string]string{"error": "Not found."}
	case errors.As(err, &in):
		status, body = http.StatusBadRequest, map[string]string{"error": in.Error()}
	default:
		s.log.Error("upload failed", "path", r.URL.Path, "err", err)
		status, body = http.StatusInternalServerError, map[string]string{"error": "Internal error, see the app logs."}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// verifyUpload compares a checksum from the user with the stored one, for
// files that arrived through the File Manager.
func (s *Server) verifyUpload(w http.ResponseWriter, r *http.Request) {
	up, role, err := s.authorizeUpload(r)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	want, err := uploads.NormalizeSHA256(r.PostForm.Get("sha256"))
	if err == nil && want == "" {
		err = errors.New("enter the SHA-256 checksum of your copy of the file")
	}
	if err != nil {
		s.userError(w, r, badInput(err.Error()+"."))
		return
	}
	if up.SHA256 == "" {
		s.userError(w, r, badInput("The checksum of this file is still being calculated. Try again in a moment."))
		return
	}
	if want != up.SHA256 {
		s.audit(r, "upload.verify", role.Name, fmt.Sprintf("file=%s result=mismatch", up.FileName))
		s.userError(w, r, badInput(fmt.Sprintf("Checksum mismatch: the file on the server has %s, yours is %s. Upload it again.", up.SHA256, want)))
		return
	}
	if err := s.store.SetUploadVerified(r.Context(), up.ID, "user"); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, "upload.verify", role.Name, fmt.Sprintf("file=%s result=match", up.FileName))
	http.Redirect(w, r, "/roles/"+role.Name+"/uploads", http.StatusSeeOther)
}

// HashLoop calculates checksums of files that were copied in with the File
// Manager, one at a time.
func (s *Server) HashLoop(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		pending, err := s.store.PendingHashes(ctx)
		if err != nil && ctx.Err() == nil {
			s.log.Error("listing uploads to hash", "err", err)
		}
		for _, up := range pending {
			if ctx.Err() != nil {
				return
			}
			s.hashUpload(ctx, up)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.hashWake:
		}
	}
}

func (s *Server) hashUpload(ctx context.Context, up store.Upload) {
	path, err := uploads.Path(s.cfg.UploadDir, up.RoleName, up.FileName)
	if err != nil {
		return
	}
	before, err := os.Stat(path)
	if err != nil {
		return
	}
	sum, err := uploads.HashFile(path)
	if err != nil {
		s.log.Error("hashing upload", "file", up.FileName, "err", err)
		return
	}
	// SetUploadHash only applies when size and mtime still match the scan
	if err := s.store.SetUploadHash(ctx, up.ID, store.FileState{Size: before.Size(), MTime: before.ModTime()}, sum); err != nil {
		s.log.Error("storing upload checksum", "file", up.FileName, "err", err)
	}
}

func (s *Server) wakeHasher() {
	select {
	case s.hashWake <- struct{}{}:
	default:
	}
}

// placeUpload moves the finished upload to a free name, never over an existing file.
func (s *Server) placeUpload(tmp, dir, name string) (string, error) {
	s.uploadMu.Lock()
	defer s.uploadMu.Unlock()
	ext := filepath.Ext(name)
	base := strings.TrimSuffix(name, ext)
	for i := 0; i < 1000; i++ {
		candidate := name
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d%s", base, i, ext)
		}
		if !uploads.ValidName(candidate) {
			continue
		}
		// a hard link fails if the target exists, unlike rename
		if err := os.Link(tmp, filepath.Join(dir, candidate)); err == nil {
			return candidate, os.Remove(tmp)
		} else if !errors.Is(err, os.ErrExist) {
			return "", err
		}
	}
	return "", errors.New("no free file name")
}

func (s *Server) keepUpload(w http.ResponseWriter, r *http.Request) {
	up, role, err := s.authorizeUpload(r)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	keep := r.PostForm.Get("keep") == "1"
	if err := s.store.SetUploadKeep(r.Context(), up.ID, keep); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, "upload.keep", role.Name, fmt.Sprintf("file=%s keep=%t", up.FileName, keep))
	http.Redirect(w, r, "/roles/"+role.Name+"/uploads", http.StatusSeeOther)
}

func (s *Server) deleteUpload(w http.ResponseWriter, r *http.Request) {
	up, role, err := s.authorizeUpload(r)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	if inUse, err := s.store.UploadInUse(r.Context(), up.ID); err != nil || inUse {
		if err == nil {
			err = badInput("This file is being imported right now. Delete it after the import has finished.")
		}
		s.userError(w, r, err)
		return
	}
	if err := s.removeUpload(r.Context(), *up); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, "upload.delete", role.Name, "file="+up.FileName)
	http.Redirect(w, r, "/roles/"+role.Name+"/uploads", http.StatusSeeOther)
}

func (s *Server) removeUpload(ctx context.Context, up store.Upload) error {
	path, err := uploads.Path(s.cfg.UploadDir, up.RoleName, up.FileName)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.store.DeleteUpload(ctx, up.ID)
}

func (s *Server) importUpload(w http.ResponseWriter, r *http.Request) {
	up, role, err := s.authorizeUpload(r)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	target := r.PostForm.Get("database")
	db, err := s.authorizeDatabase(r, target)
	if err == nil && db.Owner != role.Name {
		err = store.ErrNotFound
	}
	if err != nil {
		s.userError(w, r, err)
		return
	}
	if r.PostForm.Get("confirm") != db.Name {
		s.userError(w, r, badInput("Type the database name to confirm the import."))
		return
	}
	if v := s.viewUpload(*up); v.FormatErr != "" {
		s.userError(w, r, badInput(v.FormatErr))
		return
	}
	strict := r.PostForm.Get("strict") == "on"
	safety := r.PostForm.Get("safety_snapshot") == "on"
	if err := s.store.EnqueueImport(r.Context(), db.Name, up.ID, strict, safety, sessionFrom(r).Username); err != nil {
		s.userError(w, r, err)
		return
	}
	s.audit(r, "database.import", db.Name, fmt.Sprintf("file=%s strict=%t safety_snapshot=%t", up.FileName, strict, safety))
	http.Redirect(w, r, "/databases/"+db.Name, http.StatusSeeOther)
}

// purgeUploads registers new files of every role and deletes expired ones.
func (s *Server) purgeUploads(ctx context.Context) {
	entries, err := os.ReadDir(s.cfg.UploadDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.log.Error("reading upload directory", "err", err)
		}
		return
	}
	for _, e := range entries {
		if e.IsDir() && uploads.ValidName(e.Name()) {
			if err := s.syncUploads(ctx, e.Name()); err != nil {
				s.log.Error("syncing uploads", "role", e.Name(), "err", err)
			}
		}
	}
	expired, err := s.store.ExpiredUploads(ctx, s.cfg.UploadKeep)
	if err != nil {
		s.log.Error("listing expired uploads", "err", err)
		return
	}
	for _, up := range expired {
		if inUse, err := s.store.UploadInUse(ctx, up.ID); err != nil || inUse {
			continue
		}
		if err := s.removeUpload(ctx, up); err != nil {
			s.log.Error("deleting expired upload", "file", up.FileName, "err", err)
			continue
		}
		s.log.Info("deleted expired upload", "role", up.RoleName, "file", up.FileName)
	}
}
