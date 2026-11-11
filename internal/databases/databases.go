// Package databases: управление MySQL/MariaDB и PostgreSQL через штатные CLI (mysql, psql).
// Все идентификаторы строго валидируются, пароли — только из безопасного алфавита.
package databases

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"goserverpanel/internal/execx"
)

const (
	MySQL    = "mysql"
	Postgres = "postgres"
)

var (
	identRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)
	passRe  = regexp.MustCompile(`^[A-Za-z0-9!@#%^*_+=.,:-]{8,64}$`)
	fileRe  = regexp.MustCompile(`^[A-Za-z0-9_.-]+\.sql\.gz$`)
)

// Допустимые сопоставления (collation → charset).
var mysqlCollations = map[string]bool{
	"utf8mb4_unicode_ci": true, "utf8mb4_general_ci": true, "utf8mb4_0900_ai_ci": true,
	"utf8mb4_bin": true, "utf8_general_ci": true, "latin1_swedish_ci": true,
}

var systemDBs = map[string]bool{
	"information_schema": true, "mysql": true, "performance_schema": true, "sys": true,
	"postgres": true, "template0": true, "template1": true,
}

type Manager struct {
	Run       *execx.Runner
	BackupDir string
}

type Status struct {
	Installed bool `json:"installed"`
}

type User struct {
	Name string `json:"name"`
	Host string `json:"host,omitempty"`
}

type Backup struct {
	File string    `json:"file"`
	Size int64     `json:"size"`
	Time time.Time `json:"time"`
}

func ValidIdent(s string) bool    { return identRe.MatchString(s) && !systemDBs[strings.ToLower(s)] }
func ValidPassword(s string) bool { return passRe.MatchString(s) }

func GeneratePassword() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *Manager) Status() map[string]Status {
	return map[string]Status{
		MySQL:    {Installed: execx.Exists("mysql")},
		Postgres: {Installed: execx.Exists("psql")},
	}
}

func checkEngine(e string) error {
	if e != MySQL && e != Postgres {
		return fmt.Errorf("неизвестная СУБД %q", e)
	}
	return nil
}

func (m *Manager) sql(ctx context.Context, engine, q string) (string, error) {
	if engine == MySQL {
		return m.Run.Query(ctx, "mysql", "-N", "-B", "-e", q)
	}
	return m.Run.QueryAs(ctx, "postgres", "psql", "-tAX", "-c", q)
}

// exec — изменяющий запрос (учитывает dry-run).
func (m *Manager) exec(ctx context.Context, engine, q string) error {
	var err error
	if engine == MySQL {
		_, err = m.Run.Do(ctx, execx.Opts{}, "mysql", "-N", "-B", "-e", q)
	} else {
		_, err = m.Run.Do(ctx, execx.Opts{User: "postgres"}, "psql", "-v", "ON_ERROR_STOP=1", "-tAX", "-c", q)
	}
	return err
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (m *Manager) ListDatabases(ctx context.Context, engine string) ([]string, error) {
	if err := checkEngine(engine); err != nil {
		return nil, err
	}
	q := "SHOW DATABASES"
	if engine == Postgres {
		q = "SELECT datname FROM pg_database WHERE NOT datistemplate"
	}
	out, err := m.sql(ctx, engine, q)
	if err != nil {
		return nil, err
	}
	res := []string{}
	for _, l := range lines(out) {
		if !systemDBs[strings.ToLower(l)] {
			res = append(res, l)
		}
	}
	sort.Strings(res)
	return res, nil
}

func (m *Manager) ListUsers(ctx context.Context, engine string) ([]User, error) {
	if err := checkEngine(engine); err != nil {
		return nil, err
	}
	res := []User{}
	if engine == MySQL {
		out, err := m.sql(ctx, engine, "SELECT User, Host FROM mysql.user WHERE User NOT IN ('root','mysql.sys','mysql.session','mysql.infoschema','mariadb.sys','debian-sys-maint','')")
		if err != nil {
			return nil, err
		}
		for _, l := range lines(out) {
			f := strings.Fields(l)
			if len(f) == 2 {
				res = append(res, User{Name: f[0], Host: f[1]})
			}
		}
		return res, nil
	}
	out, err := m.sql(ctx, engine, "SELECT rolname FROM pg_roles WHERE rolcanlogin AND rolname NOT LIKE 'pg\\_%' AND rolname <> 'postgres'")
	if err != nil {
		return nil, err
	}
	for _, l := range lines(out) {
		res = append(res, User{Name: l})
	}
	return res, nil
}

func (m *Manager) CreateUser(ctx context.Context, engine, name, pass string) error {
	if err := checkEngine(engine); err != nil {
		return err
	}
	if !ValidIdent(name) {
		return fmt.Errorf("некорректное имя пользователя (латиница/цифры/_, до 32 символов)")
	}
	if !ValidPassword(pass) {
		return fmt.Errorf("пароль: 8–64 символа из набора A-Za-z0-9!@#%%^*_+=.,:-")
	}
	if engine == MySQL {
		return m.exec(ctx, engine, fmt.Sprintf("CREATE USER '%s'@'localhost' IDENTIFIED BY '%s'", name, pass))
	}
	return m.exec(ctx, engine, fmt.Sprintf(`CREATE ROLE "%s" LOGIN PASSWORD '%s'`, name, pass))
}

func (m *Manager) DropUser(ctx context.Context, engine, name string) error {
	if err := checkEngine(engine); err != nil {
		return err
	}
	if !ValidIdent(name) {
		return fmt.Errorf("некорректное имя пользователя")
	}
	if engine == MySQL {
		return m.exec(ctx, engine, fmt.Sprintf("DROP USER '%s'@'localhost'", name))
	}
	return m.exec(ctx, engine, fmt.Sprintf(`DROP ROLE "%s"`, name))
}

// CreateDatabase создаёт БД; collation (MySQL) или encoding (PG) берутся из белого списка.
func (m *Manager) CreateDatabase(ctx context.Context, engine, name, collation, owner string) error {
	if err := checkEngine(engine); err != nil {
		return err
	}
	if !ValidIdent(name) {
		return fmt.Errorf("некорректное имя БД (латиница/цифры/_, до 32 символов)")
	}
	if engine == MySQL {
		if collation == "" {
			collation = "utf8mb4_unicode_ci"
		}
		if !mysqlCollations[collation] {
			return fmt.Errorf("кодировка %q не поддерживается", collation)
		}
		charset, _, _ := strings.Cut(collation, "_")
		return m.exec(ctx, engine, fmt.Sprintf("CREATE DATABASE `%s` CHARACTER SET %s COLLATE %s", name, charset, collation))
	}
	own := ""
	if owner != "" {
		if !ValidIdent(owner) {
			return fmt.Errorf("некорректный владелец")
		}
		own = fmt.Sprintf(` OWNER "%s"`, owner)
	}
	return m.exec(ctx, engine, fmt.Sprintf(`CREATE DATABASE "%s"%s ENCODING 'UTF8' TEMPLATE template0`, name, own))
}

func (m *Manager) DropDatabase(ctx context.Context, engine, name string) error {
	if err := checkEngine(engine); err != nil {
		return err
	}
	if !ValidIdent(name) {
		return fmt.Errorf("некорректное имя БД")
	}
	if engine == MySQL {
		return m.exec(ctx, engine, fmt.Sprintf("DROP DATABASE `%s`", name))
	}
	return m.exec(ctx, engine, fmt.Sprintf(`DROP DATABASE "%s"`, name))
}

func (m *Manager) Grant(ctx context.Context, engine, db, user string) error {
	if err := checkEngine(engine); err != nil {
		return err
	}
	if !ValidIdent(db) || !ValidIdent(user) {
		return fmt.Errorf("некорректные имена")
	}
	if engine == MySQL {
		if err := m.exec(ctx, engine, fmt.Sprintf("GRANT ALL PRIVILEGES ON `%s`.* TO '%s'@'localhost'", db, user)); err != nil {
			return err
		}
		return m.exec(ctx, engine, "FLUSH PRIVILEGES")
	}
	return m.exec(ctx, engine, fmt.Sprintf(`GRANT ALL PRIVILEGES ON DATABASE "%s" TO "%s"`, db, user))
}

// Backup делает gzip-дамп в BackupDir и возвращает имя файла.
func (m *Manager) Backup(ctx context.Context, w io.Writer, engine, db string) (string, error) {
	if err := checkEngine(engine); err != nil {
		return "", err
	}
	if !ValidIdent(db) {
		return "", fmt.Errorf("некорректное имя БД")
	}
	if err := os.MkdirAll(m.BackupDir, 0o700); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s_%s_%s.sql.gz", engine, db, time.Now().Format("20060102-150405"))
	path := filepath.Join(m.BackupDir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	gz := gzip.NewWriter(f)
	var o execx.Opts
	var cmd string
	var args []string
	if engine == MySQL {
		cmd, args = "mysqldump", []string{"--single-transaction", "--routines", "--events", db}
	} else {
		cmd, args, o.User = "pg_dump", []string{db}, "postgres"
	}
	o.Stdout = gz
	fmt.Fprintf(w, "→ %s %s\n", cmd, strings.Join(args, " "))
	_, err = m.Run.Do(ctx, o, cmd, args...)
	if cerr := gz.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return name, nil
}

// Restore загружает дамп из BackupDir в существующую БД.
func (m *Manager) Restore(ctx context.Context, w io.Writer, engine, db, file string) error {
	if err := checkEngine(engine); err != nil {
		return err
	}
	if !ValidIdent(db) {
		return fmt.Errorf("некорректное имя БД")
	}
	p, err := m.BackupPath(file)
	if err != nil {
		return err
	}
	f, err := os.Open(p)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	o := execx.Opts{Stdin: gz, Stdout: w}
	if engine == MySQL {
		_, err = m.Run.Do(ctx, o, "mysql", db)
	} else {
		o.User = "postgres"
		_, err = m.Run.Do(ctx, o, "psql", "-v", "ON_ERROR_STOP=1", "-d", db)
	}
	return err
}

func (m *Manager) BackupPath(file string) (string, error) {
	if !fileRe.MatchString(file) {
		return "", fmt.Errorf("некорректное имя файла")
	}
	return filepath.Join(m.BackupDir, file), nil
}

func (m *Manager) ListBackups() []Backup {
	res := []Backup{}
	ents, _ := os.ReadDir(m.BackupDir)
	for _, e := range ents {
		if e.IsDir() || !fileRe.MatchString(e.Name()) {
			continue
		}
		if info, err := e.Info(); err == nil {
			res = append(res, Backup{File: e.Name(), Size: info.Size(), Time: info.ModTime()})
		}
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Time.After(res[j].Time) })
	return res
}
