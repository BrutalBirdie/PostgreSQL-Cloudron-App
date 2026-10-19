package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"pgpanel/internal/hba"
	"pgpanel/internal/store"
	"pgpanel/internal/tuning"
)

// Settings of the PostgreSQL parameters admins change in the panel.
const (
	SettingTuning          = "server_params"           // JSON object, name to value
	SettingTuningRequested = "server_params_requested" // set by the panel after a change
	SettingTuningError     = "server_params_error"     // last apply error, empty when it worked
)

// ApplyTuning writes the admin's parameters when the panel asks for it. The
// panel cannot write the include file itself: PostgreSQL reads it, and a
// panel that could write arbitrary parameters could run commands as postgres.
func (w *Worker) ApplyTuning(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		requested, err := w.store.TakeSetting(ctx, SettingTuningRequested)
		if err != nil && ctx.Err() == nil {
			w.log.Error("reading the parameter change request", "err", err)
		}
		if requested {
			msg := ""
			if err := w.applyTuning(ctx); err != nil {
				w.log.Error("applying server parameters", "err", err)
				msg = err.Error()
			} else {
				w.log.Info("server parameters applied")
			}
			if err := w.store.SetSetting(ctx, SettingTuningError, msg); err != nil {
				w.log.Error("storing the parameter apply result", "err", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (w *Worker) applyTuning(ctx context.Context) error {
	content, invalid, err := TuningFile(ctx, w.store)
	if err != nil {
		return err
	}
	if len(invalid) > 0 {
		return errors.Join(invalid...)
	}
	old, err := os.ReadFile(w.cfg.TuningFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := hba.WriteFileAtomic(w.cfg.TuningFile, content, 0o644); err != nil {
		return err
	}
	problems, err := w.store.ConfigFileErrors(ctx)
	if err == nil && len(problems) > 0 {
		err = fmt.Errorf("PostgreSQL rejected the settings, nothing changed: %s", strings.Join(problems, "; "))
	}
	if err == nil {
		err = w.store.ReloadConfig(ctx)
	}
	if err != nil {
		if rerr := hba.WriteFileAtomic(w.cfg.TuningFile, string(old), 0o644); rerr != nil {
			w.log.Error("restoring the previous parameters", "err", rerr)
		}
		return err
	}
	return nil
}

// TuningFile renders the stored parameters after validating them again.
// Invalid ones, for example after the memory limit was lowered, are left out
// and returned.
func TuningFile(ctx context.Context, st *store.Store) (string, []error, error) {
	raw, err := st.Setting(ctx, SettingTuning)
	if err != nil {
		return "", nil, err
	}
	values, err := tuning.Decode(raw)
	if err != nil {
		return "", nil, fmt.Errorf("stored parameters: %w", err)
	}
	clean, invalid := tuning.Validate(values, tuning.MemoryMB())
	return tuning.Render(clean), invalid, nil
}
