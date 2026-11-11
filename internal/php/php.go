// Package php: обнаружение версий PHP-FPM, модули и php.ini (через apt/phpenmod).
package php

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"goserverpanel/internal/config"
	"goserverpanel/internal/execx"
)

var Supported = []string{"7.4", "8.1", "8.2", "8.3", "8.4"}

var (
	VerRe    = regexp.MustCompile(`^\d\.\d$`)
	ModRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)
	iniValRe = regexp.MustCompile(`^[A-Za-z0-9_./:+\- ]{1,64}$`)
)

// Разрешённые директивы php.ini для редактирования из интерфейса.
var IniKeys = []string{"memory_limit", "upload_max_filesize", "post_max_size", "max_execution_time", "max_input_vars", "display_errors", "date.timezone", "opcache.enable"}

type Version struct {
	Version   string `json:"version"`
	Installed bool   `json:"installed"`
	Socket    string `json:"socket"`
	Service   string `json:"service"`
}

type Module struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Loaded    bool   `json:"loaded"`
}

type Manager struct {
	Cfg *config.Config
	Run *execx.Runner
}

func (m *Manager) Socket(ver string) string {
	return filepath.Join(m.Cfg.PHPSocketDir, "php"+ver+"-fpm.sock")
}

func (m *Manager) Versions() []Version {
	have := map[string]bool{}
	dirs, _ := filepath.Glob(filepath.Join(m.Cfg.PHPEtcDir, "*", "fpm"))
	for _, d := range dirs {
		have[filepath.Base(filepath.Dir(d))] = true
	}
	set := map[string]bool{}
	for _, v := range Supported {
		set[v] = true
	}
	for v := range have {
		set[v] = true
	}
	var list []string
	for v := range set {
		if VerRe.MatchString(v) {
			list = append(list, v)
		}
	}
	sort.Strings(list)
	out := []Version{}
	for _, v := range list {
		out = append(out, Version{Version: v, Installed: have[v], Socket: m.Socket(v), Service: "php" + v + "-fpm"})
	}
	return out
}

func (m *Manager) Installed(ver string) bool {
	for _, v := range m.Versions() {
		if v.Version == ver {
			return v.Installed
		}
	}
	return false
}

// Install устанавливает php-fpm выбранной версии (вывод — в w).
func (m *Manager) Install(ctx context.Context, w io.Writer, ver string) error {
	if !VerRe.MatchString(ver) {
		return fmt.Errorf("некорректная версия")
	}
	o := execx.Opts{Stdout: w}
	if !m.Run.DryRun && execx.Exists("add-apt-repository") {
		if _, err := os.Stat("/etc/apt/sources.list.d"); err == nil {
			ents, _ := filepath.Glob("/etc/apt/sources.list.d/*ondrej*")
			if len(ents) == 0 {
				fmt.Fprintln(w, "→ Подключаю репозиторий ondrej/php")
				if _, err := m.Run.Do(ctx, o, "add-apt-repository", "-y", "ppa:ondrej/php"); err != nil {
					fmt.Fprintln(w, "  (не удалось подключить репозиторий, продолжаю со штатным)")
				}
			}
		}
	}
	fmt.Fprintln(w, "→ apt-get update")
	if _, err := m.Run.Do(ctx, o, "apt-get", "update"); err != nil {
		return err
	}
	pk := []string{"install", "-y", "php" + ver + "-fpm", "php" + ver + "-cli", "php" + ver + "-common"}
	fmt.Fprintln(w, "→ apt-get", strings.Join(pk, " "))
	_, err := m.Run.Do(ctx, o, "apt-get", pk...)
	return err
}

func (m *Manager) Modules(ctx context.Context, ver string) ([]Module, error) {
	if !VerRe.MatchString(ver) {
		return nil, fmt.Errorf("некорректная версия")
	}
	loaded := map[string]bool{}
	if out, err := m.Run.Query(ctx, "php"+ver, "-m"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			l = strings.ToLower(strings.TrimSpace(l))
			if l != "" && !strings.HasPrefix(l, "[") {
				loaded[l] = true
			}
		}
	}
	installed := map[string]bool{}
	if out, err := m.Run.Query(ctx, "dpkg-query", "-W", "-f=${Package} ${Status}\n", "php"+ver+"-*"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			f := strings.Fields(l)
			if len(f) >= 4 && f[len(f)-1] == "installed" {
				installed[strings.TrimPrefix(f[0], "php"+ver+"-")] = true
			}
		}
	}
	avail := map[string]bool{}
	if out, err := m.Run.Query(ctx, "apt-cache", "pkgnames", "php"+ver+"-"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if l = strings.TrimSpace(l); strings.HasPrefix(l, "php"+ver+"-") {
				avail[strings.TrimPrefix(l, "php"+ver+"-")] = true
			}
		}
	}
	names := map[string]bool{}
	for k := range installed {
		names[k] = true
	}
	for k := range avail {
		names[k] = true
	}
	for _, k := range []string{"curl", "gd", "imagick", "redis", "opcache", "mbstring", "xml", "zip", "mysql", "pgsql", "intl", "bcmath", "sqlite3", "soap", "memcached", "xdebug"} {
		names[k] = true
	}
	var list []string
	for k := range names {
		if ModRe.MatchString(k) && k != "fpm" && k != "cli" && k != "common" && k != "dev" && k != "dbg" && k != "cgi" && k != "phpdbg" && k != "embed" && k != "apcu-bc" {
			list = append(list, k)
		}
	}
	sort.Strings(list)
	out := make([]Module, 0, len(list))
	for _, k := range list {
		out = append(out, Module{Name: k, Installed: installed[k] || loaded[k], Loaded: loaded[k]})
	}
	return out, nil
}

// ModuleAction: install | remove (apt, в фоне) и enable | disable (phpenmod/phpdismod).
func (m *Manager) ModuleAction(ctx context.Context, w io.Writer, ver, name, action string) error {
	if !VerRe.MatchString(ver) || !ModRe.MatchString(name) {
		return fmt.Errorf("некорректные параметры")
	}
	o := execx.Opts{Stdout: w}
	pkg := "php" + ver + "-" + name
	switch action {
	case "install":
		if _, err := m.Run.Do(ctx, o, "apt-get", "install", "-y", pkg); err != nil {
			return err
		}
	case "remove":
		if _, err := m.Run.Do(ctx, o, "apt-get", "remove", "-y", pkg); err != nil {
			return err
		}
	case "enable":
		if _, err := m.Run.Do(ctx, o, "phpenmod", "-v", ver, "-s", "fpm", name); err != nil {
			return err
		}
	case "disable":
		if _, err := m.Run.Do(ctx, o, "phpdismod", "-v", ver, "-s", "fpm", name); err != nil {
			return err
		}
	default:
		return fmt.Errorf("неизвестное действие %q", action)
	}
	return m.restart(ctx, w, ver)
}

func (m *Manager) restart(ctx context.Context, w io.Writer, ver string) error {
	_, err := m.Run.Do(ctx, execx.Opts{Stdout: w}, "systemctl", "restart", "php"+ver+"-fpm")
	return err
}

func (m *Manager) iniPath(ver string) string {
	return filepath.Join(m.Cfg.PHPEtcDir, ver, "fpm", "conf.d", "99-goserverpanel.ini")
}

func (m *Manager) ReadIni(ver string) (map[string]string, error) {
	if !VerRe.MatchString(ver) {
		return nil, fmt.Errorf("некорректная версия")
	}
	res := map[string]string{}
	f, err := os.Open(m.iniPath(ver))
	if err != nil {
		if os.IsNotExist(err) {
			return res, nil
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok && !strings.HasPrefix(strings.TrimSpace(k), ";") {
			res[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return res, nil
}

// WriteIni сохраняет только разрешённые директивы и перезапускает пул PHP-FPM.
func (m *Manager) WriteIni(ctx context.Context, ver string, vals map[string]string) error {
	if !VerRe.MatchString(ver) {
		return fmt.Errorf("некорректная версия")
	}
	allowed := map[string]bool{}
	for _, k := range IniKeys {
		allowed[k] = true
	}
	var keys []string
	for k, v := range vals {
		if !allowed[k] {
			return fmt.Errorf("директива %q не разрешена", k)
		}
		if !iniValRe.MatchString(v) {
			return fmt.Errorf("недопустимое значение для %s", k)
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString("; Managed by GoServerPanel\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "%s = %s\n", k, vals[k])
	}
	p := m.iniPath(ver)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		return err
	}
	return m.restart(ctx, io.Discard, ver)
}
