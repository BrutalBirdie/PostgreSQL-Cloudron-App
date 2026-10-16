package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
	if !canManage(sessionFrom(r), role) {
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
	sizes := make(map[string]int64, len(files))
	for _, f := range files {
		sizes[f.Name] = f.Size
	}
	return s.store.SyncUploads(ctx, role, sizes, "file manager")
}

type uploadView struct {
	store.Upload
	Format    string
	FormatErr string
	Expires   time.Time
}

type uploadsData struct {
	Role     store.Role
	Uploads  []uploadView
	Dir      string
	KeepDays int
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
	s.render(w, r, http.StatusOK, "uploads", uploadsData{Role: *role, Uploads: views, Dir: s.uploadDir(role.Name), KeepDays: int(s.cfg.UploadKeep.Hours() / 24)})
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

// uploadFile streams a multipart upload to disk. The form sends the CSRF token
// as the first part, so it is checked before any file data is written.
func (s *Server) uploadFile(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	role, err := s.authorizeRole(r, r.PathValue("name"))
	if err != nil {
		s.userError(w, r, err)
		return
	}
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Time{})
	rc.SetWriteDeadline(time.Time{})

	mr, err := r.MultipartReader()
	if err != nil {
		s.userError(w, r, badInput("Expected a file upload."))
		return
	}
	part, err := mr.NextPart()
	if err != nil || part.FormName() != "csrf" {
		s.fail(w, r, http.StatusForbidden, "The request could not be verified. Reload the page and try again.")
		return
	}
	token, _ := io.ReadAll(io.LimitReader(part, 256))
	if !s.validCSRF(r, sess, string(token)) {
		s.fail(w, r, http.StatusForbidden, "The request could not be verified. Reload the page and try again.")
		return
	}
	part, err = mr.NextPart()
	if err != nil || part.FormName() != "file" || part.FileName() == "" {
		s.userError(w, r, badInput("Choose a file to upload."))
		return
	}

	dir := s.uploadDir(role.Name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		s.internalError(w, r, err)
		return
	}
	suffix := make([]byte, 6)
	rand.Read(suffix)
	tmp := filepath.Join(dir, ".uploading-"+hex.EncodeToString(suffix))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	size, copyErr := io.Copy(f, part)
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil {
		os.Remove(tmp)
		s.log.Warn("upload aborted", "role", role.Name, "err", errors.Join(copyErr, closeErr))
		s.userError(w, r, badInput("The upload was interrupted. Try again, or copy large files with the Cloudron File Manager."))
		return
	}

	name, err := s.placeUpload(tmp, dir, uploads.SanitizeName(part.FileName()))
	if err != nil {
		os.Remove(tmp)
		s.internalError(w, r, err)
		return
	}
	if err := s.store.AddUpload(r.Context(), role.Name, name, size, sess.Username); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, "upload.create", role.Name, fmt.Sprintf("file=%s size=%d", name, size))
	http.Redirect(w, r, "/roles/"+role.Name+"/uploads", http.StatusSeeOther)
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

type importData struct {
	Upload   uploadView
	Role     store.Role
	Database string
}

func (s *Server) importPage(w http.ResponseWriter, r *http.Request) {
	up, role, err := s.authorizeUpload(r)
	if err != nil {
		s.userError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "import", importData{Upload: s.viewUpload(*up), Role: *role, Database: r.URL.Query().Get("database")})
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
	if err := s.store.EnqueueImport(r.Context(), db.Name, up.ID, strict, sessionFrom(r).Username); err != nil {
		s.userError(w, r, err)
		return
	}
	s.audit(r, "database.import", db.Name, fmt.Sprintf("file=%s strict=%t", up.FileName, strict))
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
