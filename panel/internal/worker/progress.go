package worker

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// reporter stores the progress of the running job. pct is -1 when the total is
// unknown. Writes are throttled, a step change is written at once.
type reporter struct {
	mu       sync.Mutex
	save     func(pct int, step string)
	lastStep string
	lastAt   time.Time
}

type reporterKey struct{}

func withReporter(ctx context.Context, save func(pct int, step string)) context.Context {
	return context.WithValue(ctx, reporterKey{}, &reporter{save: save})
}

func report(ctx context.Context, pct int, step string) {
	r, ok := ctx.Value(reporterKey{}).(*reporter)
	if !ok {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if step == r.lastStep && time.Since(r.lastAt) < 2*time.Second {
		return
	}
	r.lastStep, r.lastAt = step, time.Now()
	r.save(pct, step)
}

func percent(done, total int64) int {
	if total <= 0 {
		return -1
	}
	p := int(done * 100 / total)
	return min(max(p, 0), 100)
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// hashWithProgress is uploads.HashFile with progress reports.
func hashWithProgress(ctx context.Context, path string, hash io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	buf := make([]byte, 8<<20)
	var done int64
	for {
		n, err := f.Read(buf)
		if n > 0 {
			hash.Write(buf[:n])
			done += int64(n)
			report(ctx, percent(done, info.Size()), "Checking the SHA-256 of the file")
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// filePosition reads how far process pid has read into path, from /proc.
func filePosition(pid int, path string) (int64, bool) {
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return 0, false
	}
	for _, fd := range fds {
		target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name()))
		if err != nil || target != path {
			continue
		}
		info, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%s", pid, fd.Name()))
		if err != nil {
			return 0, false
		}
		for _, line := range strings.Split(string(info), "\n") {
			if v, ok := strings.CutPrefix(line, "pos:"); ok {
				pos, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
				return pos, err == nil
			}
		}
	}
	return 0, false
}

// restoreStep turns a pg_restore --verbose line into a step for the UI, ""
// for lines that are not progress (errors, warnings, details).
func restoreStep(line string) string {
	msg, ok := strings.CutPrefix(line, "pg_restore: ")
	if !ok || strings.HasPrefix(msg, "error:") || strings.HasPrefix(msg, "warning:") || strings.HasPrefix(msg, "detail:") || strings.HasPrefix(msg, "hint:") {
		return ""
	}
	return strings.ToUpper(msg[:1]) + msg[1:]
}

// tracked runs a tool, feeds its stderr lines to onLine and calls poll every
// second with the process id. Lines that are not progress are kept for the error.
func (w *Worker) tracked(ctx context.Context, onLine func(string), poll func(pid int), tool string, args ...string) error {
	cmd := exec.CommandContext(ctx, filepath.Join(w.cfg.BinDir, tool), args...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var problems []string
	lines := make(chan struct{})
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			if onLine != nil && restoreStep(line) != "" {
				onLine(line)
				continue
			}
			if len(problems) < 20 {
				problems = append(problems, line)
			}
		}
	}()
	done := make(chan error, 1)
	go func() {
		<-lines
		done <- cmd.Wait()
	}()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case err := <-done:
			if err != nil {
				msg := strings.TrimSpace(strings.Join(problems, "\n"))
				if len(msg) > 800 {
					msg = msg[:800] + "..."
				}
				return fmt.Errorf("%s: %v: %s", tool, err, msg)
			}
			return nil
		case <-t.C:
			if poll != nil {
				poll(cmd.Process.Pid)
			}
		}
	}
}

// restoreArchive runs pg_restore and reports how far it has read the archive
// and what it is doing. Table data is stored in file order, so the read
// position is the progress; indexes are built after the last data block.
func (w *Worker) restoreArchive(ctx context.Context, file string, args ...string) error {
	info, err := os.Stat(file)
	if err != nil {
		return err
	}
	var mu sync.Mutex
	step := "Starting pg_restore"
	pct := 0
	update := func() { report(ctx, pct, step) }
	update()
	return w.tracked(ctx,
		func(line string) {
			mu.Lock()
			defer mu.Unlock()
			step = restoreStep(line)
			update()
		},
		func(pid int) {
			mu.Lock()
			defer mu.Unlock()
			if pos, ok := filePosition(pid, file); ok {
				pct = percent(pos, info.Size())
			}
			update()
		},
		"pg_restore", append(append([]string{"--verbose"}, args...), file)...)
}

// dumpDatabase runs pg_dump and reports the bytes written so far.
func (w *Worker) dumpDatabase(ctx context.Context, step, out string, args ...string) error {
	report(ctx, -1, step)
	return w.tracked(ctx, nil,
		func(int) {
			if info, err := os.Stat(out); err == nil {
				report(ctx, -1, step+": "+humanBytes(info.Size())+" written")
			}
		},
		"pg_dump", append(args, "--file="+out)...)
}
