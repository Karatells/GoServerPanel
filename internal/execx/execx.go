// Package execx — единая точка запуска внешних команд (без shell, с таймаутами и dry-run).
package execx

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Runner struct {
	DryRun bool
	Log    func(format string, args ...any)
}

type Opts struct {
	Env     []string
	Dir     string
	Stdin   io.Reader
	Stdout  io.Writer // если задан, stdout уходит сюда, а в результат попадает только stderr
	User    string    // запуск от имени пользователя через runuser
	Timeout time.Duration
}

func Exists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func (r *Runner) logf(f string, a ...any) {
	if r.Log != nil {
		r.Log(f, a...)
	}
}

func (r *Runner) run(ctx context.Context, o Opts, name string, args []string) (string, error) {
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	if o.User != "" {
		args = append([]string{"-u", o.User, "--", name}, args...)
		name = "runuser"
	}
	c := exec.CommandContext(ctx, name, args...)
	c.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C.UTF-8")
	c.Env = append(c.Env, o.Env...)
	c.Dir = o.Dir
	c.Stdin = o.Stdin
	var buf bytes.Buffer
	if o.Stdout != nil {
		c.Stdout = o.Stdout
		c.Stderr = &buf
	} else {
		c.Stdout = &buf
		c.Stderr = &buf
	}
	err := c.Run()
	out := strings.TrimRight(buf.String(), "\n")
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", name, err, tail(out, 2000))
	}
	return out, nil
}

// Do выполняет изменяющую команду (учитывает dry-run).
func (r *Runner) Do(ctx context.Context, o Opts, name string, args ...string) (string, error) {
	r.logf("exec: %s %s", name, strings.Join(args, " "))
	if r.DryRun {
		return "(dry-run) " + name + " " + strings.Join(args, " "), nil
	}
	return r.run(ctx, o, name, args)
}

// Query выполняет читающую команду (всегда реально, даже в dry-run).
func (r *Runner) Query(ctx context.Context, name string, args ...string) (string, error) {
	return r.run(ctx, Opts{Timeout: 2 * time.Minute}, name, args)
}

func (r *Runner) QueryAs(ctx context.Context, user, name string, args ...string) (string, error) {
	return r.run(ctx, Opts{Timeout: 2 * time.Minute, User: user}, name, args)
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
