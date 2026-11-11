// Package store — встроенное хранилище состояния панели (атомарно сохраняемый JSON, 0600).
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type User struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	PassHash    string    `json:"-"`
	Role        string    `json:"role"` // admin | viewer
	TOTPSecret  string    `json:"-"`
	TOTPEnabled bool      `json:"totp_enabled"`
	Created     time.Time `json:"created"`
}

type ProxyRule struct {
	Path      string   `json:"path"`
	Upstreams []string `json:"upstreams"`
	WebSocket bool     `json:"websocket"`
	Balance   string   `json:"balance"` // round_robin | least_conn | ip_hash
}

type Redirect struct {
	From string `json:"from"`
	To   string `json:"to"`
	Code int    `json:"code"`
}

type Site struct {
	ID         string      `json:"id"`
	Domain     string      `json:"domain"`
	Aliases    []string    `json:"aliases"`
	Root       string      `json:"root"`
	PHPVersion string      `json:"php_version"`
	Enabled    bool        `json:"enabled"`
	ForceHTTPS bool        `json:"force_https"`
	CertID     string      `json:"cert_id"`
	Proxies    []ProxyRule `json:"proxies"`
	Redirects  []Redirect  `json:"redirects"`
	Cache      bool        `json:"cache"`
	MaxBody    string      `json:"max_body"`
	RawConfig  string      `json:"raw_config"` // если не пусто — используется вместо сгенерированного
	CMS        string      `json:"cms,omitempty"`
	Created    time.Time   `json:"created"`
}

type CertMeta struct {
	Serial    string    `json:"serial"`
	Domain    string    `json:"domain"`
	SANs      []string  `json:"sans"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Revoked   bool      `json:"revoked"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
}

type Audit struct {
	Time   time.Time `json:"time"`
	User   string    `json:"user"`
	IP     string    `json:"ip"`
	Action string    `json:"action"`
	Detail string    `json:"detail"`
}

type Data struct {
	JWTSecret string     `json:"jwt_secret"`
	Users     []User     `json:"users"`
	Sites     []Site     `json:"sites"`
	Certs     []CertMeta `json:"certs"`
	Audit     []Audit    `json:"audit"`
}

// userDisk хранит поля, скрытые в JSON API.
type userDisk struct {
	User
	PassHash   string `json:"pass_hash"`
	TOTPSecret string `json:"totp_secret"`
}

type diskData struct {
	JWTSecret string     `json:"jwt_secret"`
	Users     []userDisk `json:"users"`
	Sites     []Site     `json:"sites"`
	Certs     []CertMeta `json:"certs"`
	Audit     []Audit    `json:"audit"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	d    Data
}

func NewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: path}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		var dd diskData
		if err := json.Unmarshal(raw, &dd); err != nil {
			return nil, err
		}
		s.d = Data{JWTSecret: dd.JWTSecret, Sites: dd.Sites, Certs: dd.Certs, Audit: dd.Audit}
		for _, u := range dd.Users {
			u.User.PassHash, u.User.TOTPSecret = u.PassHash, u.TOTPSecret
			s.d.Users = append(s.d.Users, u.User)
		}
	case os.IsNotExist(err):
	default:
		return nil, err
	}
	if s.d.JWTSecret == "" {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		s.d.JWTSecret = hex.EncodeToString(b)
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// View даёт read-only доступ; функция не должна сохранять ссылки на данные.
func (s *Store) View(fn func(d *Data)) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	fn(&s.d)
}

// Update выполняет изменение; при ошибке из fn состояние откатывается и не сохраняется.
func (s *Store) Update(fn func(d *Data) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snapshot, _ := json.Marshal(toDisk(s.d))
	if err := fn(&s.d); err != nil {
		var dd diskData
		_ = json.Unmarshal(snapshot, &dd)
		s.d = fromDisk(dd)
		return err
	}
	if len(s.d.Audit) > 2000 {
		s.d.Audit = s.d.Audit[len(s.d.Audit)-1000:]
	}
	return s.save()
}

func toDisk(d Data) diskData {
	dd := diskData{JWTSecret: d.JWTSecret, Sites: d.Sites, Certs: d.Certs, Audit: d.Audit}
	for _, u := range d.Users {
		dd.Users = append(dd.Users, userDisk{User: u, PassHash: u.PassHash, TOTPSecret: u.TOTPSecret})
	}
	return dd
}

func fromDisk(dd diskData) Data {
	d := Data{JWTSecret: dd.JWTSecret, Sites: dd.Sites, Certs: dd.Certs, Audit: dd.Audit}
	for _, u := range dd.Users {
		u.User.PassHash, u.User.TOTPSecret = u.PassHash, u.TOTPSecret
		d.Users = append(d.Users, u.User)
	}
	return d
}

func (s *Store) save() error {
	raw, err := json.MarshalIndent(toDisk(s.d), "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
