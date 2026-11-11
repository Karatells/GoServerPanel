package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"goserverpanel/internal/auth"
	"goserverpanel/internal/config"
	"goserverpanel/internal/store"
)

type env struct {
	t   *testing.T
	srv *httptest.Server
	cfg config.Config
	cl  *http.Client
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	cfg := config.Default()
	cfg.DataDir = filepath.Join(dir, "data")
	cfg.DryRun = true
	cfg.NginxAvailable = filepath.Join(dir, "nginx", "available")
	cfg.NginxEnabled = filepath.Join(dir, "nginx", "enabled")
	cfg.NginxLogDir = filepath.Join(dir, "logs")
	cfg.WWWRoot = filepath.Join(dir, "www")
	cfg.PHPEtcDir = filepath.Join(dir, "php")
	cfg.PHPSocketDir = filepath.Join(dir, "run")
	cfg.FilesRoots = []string{cfg.WWWRoot}
	_ = os.MkdirAll(cfg.WWWRoot, 0o755)
	st, err := store.Open(filepath.Join(cfg.DataDir, "panel.json"))
	if err != nil {
		t.Fatal(err)
	}
	h, _ := auth.HashPassword("Sup3rSecretPass")
	_ = st.Update(func(d *store.Data) error {
		d.Users = append(d.Users,
			store.User{ID: "u1", Username: "admin", PassHash: h, Role: "admin"},
			store.User{ID: "u2", Username: "viewer", PassHash: h, Role: "viewer"})
		return nil
	})
	app, err := New(&cfg, st, fstest.MapFS{"index.html": {Data: []byte("<h1>ui</h1>")}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.Handler())
	t.Cleanup(srv.Close)
	return &env{t: t, srv: srv, cfg: cfg, cl: &http.Client{}}
}

func (e *env) call(method, path string, body any, cookie *http.Cookie, hdr map[string]string) (int, map[string]any, []*http.Cookie) {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("X-Requested-With", "gsp")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := e.cl.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Cookies()
}

func (e *env) login(user string) *http.Cookie {
	code, _, cookies := e.call("POST", "/api/login", map[string]string{"username": user, "password": "Sup3rSecretPass"}, nil, nil)
	if code != 200 || len(cookies) == 0 {
		e.t.Fatalf("login %s failed: %d", user, code)
	}
	return cookies[0]
}

func TestAuthAndRBAC(t *testing.T) {
	e := newEnv(t)
	if code, _, _ := e.call("GET", "/api/sites", nil, nil, nil); code != 401 {
		t.Fatalf("unauthenticated access: %d", code)
	}
	admin, viewer := e.login("admin"), e.login("viewer")
	if code, _, _ := e.call("GET", "/api/sites", nil, viewer, nil); code != 200 {
		t.Errorf("viewer read: %d", code)
	}
	if code, _, _ := e.call("POST", "/api/sites", map[string]any{"domain": "a.com"}, viewer, nil); code != 403 {
		t.Errorf("viewer write must be 403, got %d", code)
	}
	if code, _, _ := e.call("GET", "/api/files?path="+e.cfg.WWWRoot, nil, viewer, nil); code != 403 {
		t.Errorf("viewer files must be 403, got %d", code)
	}
	// CSRF: изменение по cookie без заголовка запрещено
	req, _ := http.NewRequest("POST", e.srv.URL+"/api/nginx/reload", nil)
	req.AddCookie(admin)
	resp, _ := e.cl.Do(req)
	if resp.StatusCode != 403 {
		t.Errorf("missing CSRF header must be 403, got %d", resp.StatusCode)
	}
	// неверный пароль
	if code, _, _ := e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "nope"}, nil, nil); code != 401 {
		t.Errorf("bad login: %d", code)
	}
	// логаут отзывает токен
	e.call("POST", "/api/logout", nil, admin, nil)
	if code, _, _ := e.call("GET", "/api/me", nil, admin, nil); code != 401 {
		t.Errorf("token must be revoked after logout, got %d", code)
	}
}

func TestLoginThrottle(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 5; i++ {
		e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "bad"}, nil, nil)
	}
	if code, _, _ := e.call("POST", "/api/login", map[string]string{"username": "admin", "password": "Sup3rSecretPass"}, nil, nil); code != 429 {
		t.Errorf("expected lockout (429), got %d", code)
	}
}

func TestSiteLifecycle(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin")
	code, site, _ := e.call("POST", "/api/sites", map[string]any{"domain": "Example.com", "aliases": []string{"www.example.com"}}, c, nil)
	if code != 201 {
		t.Fatalf("create: %d %v", code, site)
	}
	id := site["id"].(string)
	conf := filepath.Join(e.cfg.NginxAvailable, "gsp-example.com.conf")
	b, err := os.ReadFile(conf)
	if err != nil || !strings.Contains(string(b), "server_name example.com www.example.com;") {
		t.Fatalf("nginx config not written: %v\n%s", err, b)
	}
	if _, err := os.Lstat(filepath.Join(e.cfg.NginxEnabled, "gsp-example.com.conf")); err != nil {
		t.Error("symlink in sites-enabled missing")
	}
	if _, err := os.Stat(filepath.Join(e.cfg.WWWRoot, "example.com", "public_html", "index.html")); err != nil {
		t.Error("document root / placeholder not created")
	}
	if code, _, _ := e.call("POST", "/api/sites", map[string]any{"domain": "example.com"}, c, nil); code != 400 {
		t.Errorf("duplicate domain must be rejected, got %d", code)
	}
	if code, _, _ := e.call("POST", "/api/sites", map[string]any{"domain": "x.com; evil", "root": e.cfg.WWWRoot + "/x/y"}, c, nil); code != 400 {
		t.Errorf("injection must be rejected, got %d", code)
	}
	// ручной конфиг и возврат к генерируемому
	if code, _, _ := e.call("PUT", "/api/sites/"+id+"/config", map[string]string{"config": "server { listen 80; }"}, c, nil); code != 200 {
		t.Errorf("raw config: %d", code)
	}
	if b, _ := os.ReadFile(conf); string(b) != "server { listen 80; }" {
		t.Errorf("raw config not applied: %s", b)
	}
	e.call("PUT", "/api/sites/"+id+"/config", map[string]string{"config": ""}, c, nil)
	if b, _ := os.ReadFile(conf); !strings.Contains(string(b), "Managed by GoServerPanel") {
		t.Error("generated config not restored")
	}
	if code, _, _ := e.call("DELETE", "/api/sites/"+id, nil, c, nil); code != 200 {
		t.Errorf("delete: %d", code)
	}
	if _, err := os.Stat(conf); err == nil {
		t.Error("config must be removed on delete")
	}
}

func TestPKIFlowAndSiteAssignment(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin")
	if code, _, _ := e.call("POST", "/api/pki/ca", map[string]any{"cn": "T CA", "years": 2}, c, nil); code != 201 {
		t.Fatalf("CA: %d", code)
	}
	code, cert, _ := e.call("POST", "/api/pki/certs", map[string]any{"domain": "dev.local", "days": 30}, c, nil)
	if code != 201 {
		t.Fatalf("issue: %d %v", code, cert)
	}
	serial := cert["serial"].(string)
	code, site, _ := e.call("POST", "/api/sites", map[string]any{"domain": "dev.local", "cert_id": serial, "force_https": true}, c, nil)
	if code != 201 {
		t.Fatalf("site: %d %v", code, site)
	}
	b, _ := os.ReadFile(filepath.Join(e.cfg.NginxAvailable, "gsp-dev.local.conf"))
	if !strings.Contains(string(b), "listen 443 ssl http2;") {
		t.Fatalf("HTTPS block missing:\n%s", b)
	}
	e.call("POST", "/api/pki/certs/"+serial+"/revoke", nil, c, nil)
	b, _ = os.ReadFile(filepath.Join(e.cfg.NginxAvailable, "gsp-dev.local.conf"))
	if strings.Contains(string(b), "443") {
		t.Error("revoked certificate must be detached from the site")
	}
}

func TestFilesAPI(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin")
	p := filepath.Join(e.cfg.WWWRoot, "t.txt")
	if code, _, _ := e.call("PUT", "/api/files/write", map[string]string{"path": p, "content": "hi"}, c, nil); code != 200 {
		t.Fatalf("write: %d", code)
	}
	if code, body, _ := e.call("GET", "/api/files/read?path="+p, nil, c, nil); code != 200 || body["content"] != "hi" {
		t.Errorf("read: %d %v", code, body)
	}
	if code, _, _ := e.call("GET", "/api/files/read?path=/etc/passwd", nil, c, nil); code != 400 {
		t.Errorf("outside roots must be denied, got %d", code)
	}
}

func TestSecurityHeadersAndUI(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Get(e.srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Content-Security-Policy") == "" || resp.Header.Get("X-Frame-Options") != "DENY" {
		t.Error("security headers missing")
	}
}
