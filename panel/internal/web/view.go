package web

import (
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"pgpanel/internal/names"
	"pgpanel/internal/store"
)

var viewFuncs = template.FuncMap{
	"icon": func(name string) template.HTML {
		return template.HTML(`<svg class="i" aria-hidden="true"><use href="#i-` + template.HTMLEscapeString(name) + `"/></svg>`)
	},
	"dict": func(kv ...any) (map[string]any, error) {
		if len(kv)%2 != 0 {
			return nil, errors.New("dict needs key value pairs")
		}
		m := make(map[string]any, len(kv)/2)
		for i := 0; i < len(kv); i += 2 {
			k, ok := kv[i].(string)
			if !ok {
				return nil, errors.New("dict keys must be strings")
			}
			m[k] = kv[i+1]
		}
		return m, nil
	},
	"utc": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") + " UTC" },
	"ago": ago,
	"initials": func(name string) string {
		var out []rune
		for _, f := range strings.Fields(name) {
			out = append(out, []rune(strings.ToUpper(f))[0])
			if len(out) == 2 {
				break
			}
		}
		return string(out)
	},
	"jobTitle": jobTitle,
	"kindLabel": func(kind string) string {
		switch kind {
		case store.KindScheduled:
			return "scheduled"
		case store.KindPreRestore:
			return "before restore"
		}
		return "manual"
	},
	"duration": func(t time.Time) string { return since(time.Since(t)) },
	"add":      func(a, b int) int { return a + b },
	"reservedNames": func() string {
		list, _ := names.Reserved()
		return strings.Join(list, " ")
	},
	"reservedPrefixes": func() string {
		_, prefixes := names.Reserved()
		return strings.Join(prefixes, " ")
	},
}

func ago(t time.Time) string {
	days := int(time.Since(t).Hours() / 24)
	switch {
	case days <= 0:
		return "today"
	case days == 1:
		return "yesterday"
	}
	return strconv.Itoa(days) + " days ago"
}

func since(d time.Duration) string {
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d.Seconds())) + " s"
	case d < time.Hour:
		return strconv.Itoa(int(d.Minutes())) + " min"
	case d < 48*time.Hour:
		return strconv.Itoa(int(d.Hours())) + " h " + strconv.Itoa(int(d.Minutes())%60) + " min"
	}
	return strconv.Itoa(int(d.Hours()/24)) + " days"
}

func jobTitle(j store.Job) string {
	what := map[string]string{"snapshot": "Snapshot", "restore": "Restore", "import": "Import"}[j.Kind]
	if j.Scheduled {
		what = "Scheduled snapshot"
	}
	if j.SnapshotID != nil && j.Kind == "restore" {
		what += " of #" + strconv.FormatInt(*j.SnapshotID, 10)
	}
	return what
}

// safeNext only allows paths on this site as redirect target.
func safeNext(next, fallback string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n") {
		return fallback
	}
	return next
}

// saveAccount stores the user's preferences. The account sheet sends it with
// fetch on every change, without JavaScript it is a normal form post.
func (s *Server) saveAccount(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	p := store.Prefs{NotifyFailures: r.PostForm.Get("notify_failures") == "on", ShowLabels: r.PostForm.Get("show_labels") == "on"}
	if err := s.store.SetPrefs(r.Context(), sess.Username, p); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.audit(r, "account.prefs", sess.Username, "notify_failures="+strconv.FormatBool(p.NotifyFailures)+" show_labels="+strconv.FormatBool(p.ShowLabels))
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, safeNext(r.PostForm.Get("next"), "/"), http.StatusSeeOther)
}
