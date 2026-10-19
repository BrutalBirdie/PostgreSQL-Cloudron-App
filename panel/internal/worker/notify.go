package worker

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"pgpanel/internal/access"
	"pgpanel/internal/notify"
	"pgpanel/internal/store"
)

// SettingNotifyTo holds the admin addresses that get every failure.
const SettingNotifyTo = "notify_admin_email"

// NotifyFailures mails the owners of a database who opted in, and the admin
// addresses, when one of its jobs failed. The notified flag lives in the jobs table, so a
// restart neither repeats nor loses a mail.
func (w *Worker) NotifyFailures(ctx context.Context, interval time.Duration) {
	if w.cfg.Mailer == nil {
		w.log.Info("outgoing mail is not configured, no failure notifications")
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		w.notifyFailures(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (w *Worker) notifyFailures(ctx context.Context) {
	jobs, err := w.store.UnnotifiedFailures(ctx)
	if err != nil {
		if ctx.Err() == nil {
			w.log.Error("reading failed jobs", "err", err)
		}
		return
	}
	for _, j := range jobs {
		to := w.recipients(ctx, j.Database)
		if len(to) > 0 {
			subject, body := failureMail(j, w.cfg.Origin)
			sent, err := w.cfg.Mailer.Send(ctx, to, subject, body)
			if err != nil {
				w.log.Error("sending failure notification", "id", j.ID, "err", err)
			}
			// retried on the next round only when nobody got it, a retry would repeat it for the others
			if sent == 0 {
				continue
			}
			w.log.Info("failure notification sent", "id", j.ID, "recipients", sent)
		}
		if err := w.store.MarkNotified(ctx, j.ID); err != nil {
			w.log.Error("marking job notified", "id", j.ID, "err", err)
		}
	}
}

// recipients are the admin addresses plus the owners of the database's role
// who opted in. When the directory is down only the admin addresses are used.
func (w *Worker) recipients(ctx context.Context, database string) []string {
	setting, err := w.store.Setting(ctx, SettingNotifyTo)
	if err != nil {
		w.log.Error("reading notification addresses", "err", err)
	}
	to, err := notify.ParseList(setting)
	if err != nil {
		w.log.Error("invalid notification addresses", "err", err)
	}
	db, err := w.store.GetDatabase(ctx, database)
	if err != nil {
		return to
	}
	role, err := w.store.GetRole(ctx, db.Owner)
	if err != nil {
		return to
	}
	owners, err := w.ownerEmails(ctx, role.Owners)
	if err != nil {
		w.log.Warn("cannot resolve owner addresses, mailing the admin addresses only", "database", database, "err", err)
	}
	for _, a := range owners {
		if !slices.Contains(to, a) {
			to = append(to, a)
		}
	}
	return to
}

func (w *Worker) ownerEmails(ctx context.Context, owners []access.Principal) ([]string, error) {
	if len(owners) == 0 {
		return nil, nil
	}
	optIn, err := w.store.NotifyOptIns(ctx)
	if err != nil || len(optIn) == 0 {
		return nil, err
	}
	users, _, err := w.cfg.Directory.Directory(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, u := range users {
		if u.Email != "" && optIn[u.Username] && access.Owns(owners, u.Member()) {
			out = append(out, u.Email)
		}
	}
	return out, nil
}

func failureMail(j store.Job, origin string) (subject, body string) {
	what := j.Kind
	if j.Scheduled {
		what = "scheduled " + what
	}
	subject = fmt.Sprintf("PostgreSQL: %s of %s failed", what, j.Database)
	var b strings.Builder
	fmt.Fprintf(&b, "The %s of database %s failed.\n\n", what, j.Database)
	if j.StartedAt != nil {
		fmt.Fprintf(&b, "Started:      %s UTC\n", j.StartedAt.UTC().Format("2006-01-02 15:04"))
	}
	fmt.Fprintf(&b, "Requested by: %s\n", j.RequestedBy)
	fmt.Fprintf(&b, "Error:        %s\n\n", j.Error)
	fmt.Fprintf(&b, "Database page: %s/databases/%s\n", strings.TrimRight(origin, "/"), j.Database)
	return subject, b.String()
}
