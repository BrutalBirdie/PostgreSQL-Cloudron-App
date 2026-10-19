package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// Prefs are per Cloudron user and apply to every role the user owns.
type Prefs struct {
	NotifyFailures bool // mail when a job of a database of an owned role fails
	ShowLabels     bool // text next to every icon button
}

// Prefs returns the user's preferences, the zero value when none are stored.
func (s *Store) Prefs(ctx context.Context, username string) (Prefs, error) {
	var p Prefs
	err := s.pool.QueryRow(ctx, `SELECT notify_failures, show_labels FROM user_prefs WHERE username = $1`, username).Scan(&p.NotifyFailures, &p.ShowLabels)
	if errors.Is(err, pgx.ErrNoRows) {
		return Prefs{}, nil
	}
	return p, err
}

func (s *Store) SetPrefs(ctx context.Context, username string, p Prefs) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO user_prefs (username, notify_failures, show_labels) VALUES ($1, $2, $3)
ON CONFLICT (username) DO UPDATE SET notify_failures = EXCLUDED.notify_failures, show_labels = EXCLUDED.show_labels`, username, p.NotifyFailures, p.ShowLabels)
	return err
}

// NotifyOptIns returns the users who want failure mails.
func (s *Store) NotifyOptIns(ctx context.Context) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT username FROM user_prefs WHERE notify_failures`)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[n] = true
	}
	return out, err
}
