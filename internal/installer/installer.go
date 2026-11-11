// Package installer: каталог CMS и авторазвёртывание (скачать → распаковать → сконфигурировать → права).
package installer

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"goserverpanel/internal/execx"
)

type App struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"-"`
	Format      string `json:"-"`          // tar.gz | zip | composer
	Strip       string `json:"-"`          // "*" — убрать первый каталог; иначе — префикс, внутри которого лежит CMS
	WebSubdir   string `json:"web_subdir"` // подкаталог, который должен быть корнем сайта
	NeedsPHP    bool   `json:"needs_php"`
	AutoConfig  bool   `json:"auto_config"` // конфиг подключения к БД создаётся автоматически
	Post        string `json:"post"`        // подсказка по завершению установки
}

// Каталог. URL-адреса «latest» стабильны у WordPress и Drupal; для остальных закреплены версии —
// при необходимости их можно поменять в catalog.json (см. LoadOverrides).
var catalog = []App{
	{ID: "wordpress", Name: "WordPress", Description: "CMS №1 в мире. wp-config.php создаётся автоматически.",
		URL: "https://wordpress.org/latest.tar.gz", Format: "tar.gz", Strip: "*", NeedsPHP: true, AutoConfig: true, Post: "/wp-admin/install.php"},
	{ID: "joomla", Name: "Joomla", Description: "CMS с мастером установки (данные БД выдаются по завершении).",
		URL: "https://github.com/joomla/joomla-cms/releases/download/5.2.3/Joomla_5.2.3-Stable-Full_Package.zip", Format: "zip", NeedsPHP: true, Post: "/installation/"},
	{ID: "drupal", Name: "Drupal", Description: "Платформа для контентных проектов (данные БД выдаются по завершении).",
		URL: "https://www.drupal.org/download-latest/tar.gz", Format: "tar.gz", Strip: "*", WebSubdir: "web", NeedsPHP: true, Post: "/core/install.php"},
	{ID: "opencart", Name: "OpenCart", Description: "Интернет-магазин (данные БД выдаются по завершении).",
		URL: "https://github.com/opencart/opencart/releases/download/4.0.2.3/opencart-4.0.2.3.zip", Format: "zip", Strip: "upload/", NeedsPHP: true, Post: "/install/"},
	{ID: "laravel", Name: "Laravel Starter", Description: "composer create-project laravel/laravel; корень сайта — public/.",
		Format: "composer", WebSubdir: "public", NeedsPHP: true, Post: "/"},
}

func Catalog() []App { return append([]App(nil), catalog...) }

func Find(id string) (App, bool) {
	for _, a := range catalog {
		if a.ID == id {
			return a, true
		}
	}
	return App{}, false
}

type Params struct {
	App                            App
	Dir                            string // каталог установки
	DBName, DBUser, DBPass, DBHost string
	WebUser                        string
	PHPVersion                     string
}

func randStr(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#%^&*()-_=+[]{}<>,.?"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

// Install выполняет установку файлов CMS. Каталог должен быть пустым (или отсутствовать).
func Install(ctx context.Context, w io.Writer, run *execx.Runner, p Params) error {
	if err := os.MkdirAll(p.Dir, 0o755); err != nil {
		return err
	}
	if ents, err := os.ReadDir(p.Dir); err != nil {
		return err
	} else if len(ents) > 0 {
		return fmt.Errorf("каталог %s не пуст — установка отменена", p.Dir)
	}

	if run.DryRun {
		fmt.Fprintf(w, "(dry-run) пропускаю загрузку %s в %s\n", p.App.ID, p.Dir)
		return nil
	}
	if p.App.Format == "composer" {
		if !execx.Exists("composer") {
			return errors.New("composer не установлен в системе")
		}
		fmt.Fprintln(w, "→ composer create-project laravel/laravel")
		if _, err := run.Do(ctx, execx.Opts{Stdout: w, Env: []string{"COMPOSER_ALLOW_SUPERUSER=1"}, Timeout: 30 * time.Minute},
			"composer", "create-project", "laravel/laravel", p.Dir, "--no-interaction", "--prefer-dist"); err != nil {
			return err
		}
	} else {
		fmt.Fprintf(w, "→ Загружаю %s\n", p.App.URL)
		tmp, err := download(ctx, p.App.URL)
		if err != nil {
			return err
		}
		defer os.Remove(tmp)
		fmt.Fprintln(w, "→ Распаковываю")
		switch p.App.Format {
		case "tar.gz":
			err = extractTarGz(tmp, p.Dir, p.App.Strip)
		case "zip":
			err = extractZip(tmp, p.Dir, p.App.Strip)
		default:
			err = fmt.Errorf("неизвестный формат %q", p.App.Format)
		}
		if err != nil {
			return err
		}
	}

	fmt.Fprintln(w, "→ Настраиваю права доступа")
	if err := setPerms(p.Dir); err != nil {
		return err
	}
	if p.App.ID == "wordpress" {
		fmt.Fprintln(w, "→ Создаю wp-config.php")
		if err := writeWPConfig(p); err != nil { // после setPerms: файл с паролем БД остаётся 0640
			return err
		}
	}
	if p.WebUser != "" {
		if _, err := run.Do(ctx, execx.Opts{}, "chown", "-R", p.WebUser+":"+p.WebUser, p.Dir); err != nil {
			return err
		}
	}
	return nil
}

func download(ctx context.Context, url string) (string, error) {
	const limit = 512 << 20
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "GoServerPanel")
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("загрузка %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.CreateTemp("", "gsp-cms-*")
	if err != nil {
		return "", err
	}
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	f.Close()
	if err == nil && n > limit {
		err = errors.New("архив слишком большой")
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

// target подбирает путь внутри dst с учётом strip и защитой от path traversal.
func target(dst, name, strip string) (string, bool) {
	name = strings.TrimPrefix(path.Clean("/"+strings.ReplaceAll(name, "\\", "/")), "/")
	switch {
	case strip == "*":
		_, rest, ok := strings.Cut(name, "/")
		if !ok {
			return "", false
		}
		name = rest
	case strip != "":
		if !strings.HasPrefix(name, strip) {
			return "", false
		}
		name = strings.TrimPrefix(name, strip)
	}
	if name == "" {
		return "", false
	}
	full := filepath.Join(dst, filepath.FromSlash(name))
	if !strings.HasPrefix(full, filepath.Clean(dst)+string(filepath.Separator)) {
		return "", false
	}
	return full, true
}

func extractTarGz(file, dst, strip string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		out, ok := target(dst, h.Name, strip)
		if !ok {
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(out, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := writeFile(out, tr); err != nil {
				return err
			}
		}
		// симлинки и спецфайлы из архива намеренно игнорируются
	}
}

func extractZip(file, dst, strip string) error {
	zr, err := zip.OpenReader(file)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, zf := range zr.File {
		out, ok := target(dst, zf.Name, strip)
		if !ok {
			continue
		}
		if zf.FileInfo().IsDir() || strings.HasSuffix(zf.Name, "/") {
			if err := os.MkdirAll(out, 0o755); err != nil {
				return err
			}
			continue
		}
		if !zf.Mode().IsRegular() {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return err
		}
		err = writeFile(out, rc)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func writeFile(path string, r io.Reader) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, io.LimitReader(r, 1<<30))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func setPerms(dir string) error {
	return filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			return os.Chmod(p, 0o755)
		}
		return os.Chmod(p, 0o644)
	})
}

func phpQuote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

func writeWPConfig(p Params) error {
	sample := filepath.Join(p.Dir, "wp-config-sample.php")
	if _, err := os.Stat(sample); err != nil {
		return errors.New("wp-config-sample.php не найден в архиве")
	}
	var b strings.Builder
	b.WriteString("<?php\n// Сгенерировано GoServerPanel\n")
	fmt.Fprintf(&b, "define( 'DB_NAME', %s );\ndefine( 'DB_USER', %s );\ndefine( 'DB_PASSWORD', %s );\ndefine( 'DB_HOST', %s );\n",
		phpQuote(p.DBName), phpQuote(p.DBUser), phpQuote(p.DBPass), phpQuote(p.DBHost))
	b.WriteString("define( 'DB_CHARSET', 'utf8mb4' );\ndefine( 'DB_COLLATE', '' );\n")
	for _, k := range []string{"AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY", "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"} {
		fmt.Fprintf(&b, "define( '%s', %s );\n", k, phpQuote(randStr(64)))
	}
	b.WriteString("$table_prefix = 'wp_';\ndefine( 'WP_DEBUG', false );\n")
	b.WriteString("if ( ! defined( 'ABSPATH' ) ) {\n\tdefine( 'ABSPATH', __DIR__ . '/' );\n}\nrequire_once ABSPATH . 'wp-settings.php';\n")
	return os.WriteFile(filepath.Join(p.Dir, "wp-config.php"), []byte(b.String()), 0o640)
}
