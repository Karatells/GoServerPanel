// Package files: лёгкий файловый менеджер, ограниченный списком корневых каталогов.
package files

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	MaxEdit   = 2 << 20
	MaxUpload = 256 << 20
)

type Entry struct {
	Name  string    `json:"name"`
	IsDir bool      `json:"is_dir"`
	Size  int64     `json:"size"`
	Mode  string    `json:"mode"`
	Mod   time.Time `json:"mod"`
}

type Manager struct{ Roots []string }

func New(roots []string) *Manager {
	m := &Manager{}
	for _, r := range roots {
		if a, err := filepath.Abs(r); err == nil {
			if ev, err := filepath.EvalSymlinks(a); err == nil {
				a = ev
			}
			m.Roots = append(m.Roots, a)
		}
	}
	return m
}

func within(root, p string) bool {
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

// Resolve приводит путь к абсолютному и проверяет (включая симлинки), что он внутри разрешённого корня.
func (m *Manager) Resolve(p string) (string, error) {
	if p == "" || !filepath.IsAbs(p) {
		return "", errors.New("нужен абсолютный путь")
	}
	p = filepath.Clean(p)
	// Разрешаем симлинки по ближайшему существующему предку.
	probe, rest := p, ""
	for {
		if ev, err := filepath.EvalSymlinks(probe); err == nil {
			p = filepath.Join(ev, rest)
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", errors.New("путь недоступен")
		}
		rest = filepath.Join(filepath.Base(probe), rest)
		probe = parent
	}
	for _, r := range m.Roots {
		if within(r, p) {
			return p, nil
		}
	}
	return "", errors.New("путь вне разрешённых каталогов")
}

func (m *Manager) isRoot(p string) bool {
	for _, r := range m.Roots {
		if p == r {
			return true
		}
	}
	return false
}

func (m *Manager) List(p string) ([]Entry, error) {
	rp, err := m.Resolve(p)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(rp)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(ents))
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Entry{Name: e.Name(), IsDir: e.IsDir(), Size: info.Size(), Mode: info.Mode().String(), Mod: info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

func (m *Manager) Read(p string) (string, error) {
	rp, err := m.Resolve(p)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(rp)
	if err != nil {
		return "", err
	}
	if st.IsDir() {
		return "", errors.New("это каталог")
	}
	if st.Size() > MaxEdit {
		return "", fmt.Errorf("файл больше %d МБ — скачайте его", MaxEdit>>20)
	}
	b, err := os.ReadFile(rp)
	if err != nil {
		return "", err
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return "", errors.New("бинарный файл нельзя редактировать — скачайте его")
	}
	return string(b), nil
}

func (m *Manager) Write(p, content string) error {
	if len(content) > MaxEdit {
		return errors.New("слишком большой файл")
	}
	rp, err := m.Resolve(p)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if st, err := os.Stat(rp); err == nil {
		if st.IsDir() {
			return errors.New("это каталог")
		}
		mode = st.Mode().Perm()
	}
	return os.WriteFile(rp, []byte(content), mode)
}

func (m *Manager) Mkdir(p string) error {
	rp, err := m.Resolve(p)
	if err != nil {
		return err
	}
	return os.MkdirAll(rp, 0o755)
}

func (m *Manager) Delete(p string) error {
	rp, err := m.Resolve(p)
	if err != nil {
		return err
	}
	if m.isRoot(rp) {
		return errors.New("нельзя удалить корневой каталог")
	}
	return os.RemoveAll(rp)
}

func (m *Manager) Rename(from, to string) error {
	a, err := m.Resolve(from)
	if err != nil {
		return err
	}
	b, err := m.Resolve(to)
	if err != nil {
		return err
	}
	if m.isRoot(a) {
		return errors.New("нельзя переименовать корневой каталог")
	}
	if _, err := os.Lstat(b); err == nil {
		return errors.New("целевой путь уже существует")
	}
	return os.Rename(a, b)
}

func (m *Manager) Upload(dir, name string, r io.Reader) error {
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
		return errors.New("некорректное имя файла")
	}
	rd, err := m.Resolve(dir)
	if err != nil {
		return err
	}
	dst, err := m.Resolve(filepath.Join(rd, name))
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(r, MaxUpload+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > MaxUpload {
		_ = os.Remove(dst)
		err = errors.New("файл слишком большой")
	}
	return err
}

func (m *Manager) Open(p string) (*os.File, os.FileInfo, error) {
	rp, err := m.Resolve(p)
	if err != nil {
		return nil, nil, err
	}
	f, err := os.Open(rp)
	if err != nil {
		return nil, nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, err
	}
	if st.IsDir() {
		f.Close()
		return nil, nil, errors.New("это каталог")
	}
	return f, st, nil
}
