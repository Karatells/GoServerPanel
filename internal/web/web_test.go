package web

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"goserverpanel/internal/auth"
	"goserverpanel/internal/config"
	"goserverpanel/internal/store"
)

type env struct {
	t   *testing.T
	app *App
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
	return &env{t: t, app: app, srv: srv, cfg: cfg, cl: &http.Client{}}
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

// Регрессия: при UMask=0077 (как в старом systemd-юните) каталог сайта создавался как 0700,
// и nginx получал "stat() ... Permission denied".
func TestSiteDirsTraversableUnderRestrictiveUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	e := newEnv(t)
	c := e.login("admin")
	if code, body, _ := e.call("POST", "/api/sites", map[string]any{"domain": "wp.home"}, c, nil); code != 201 {
		t.Fatalf("create: %d %v", code, body)
	}
	for _, d := range []string{
		filepath.Join(e.cfg.WWWRoot, "wp.home"),
		filepath.Join(e.cfg.WWWRoot, "wp.home", "public_html"),
	} {
		st, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm()&0o055 != 0o055 {
			t.Errorf("%s has mode %v: nginx cannot traverse it", d, st.Mode().Perm())
		}
	}
	// FixSitePerms чинит уже существующие закрытые каталоги
	d := filepath.Join(e.cfg.WWWRoot, "wp.home")
	_ = os.Chmod(d, 0o700)
	e.app.FixSitePerms()
	if st, _ := os.Stat(d); st.Mode().Perm()&0o055 != 0o055 {
		t.Errorf("FixSitePerms did not repair %s: %v", d, st.Mode().Perm())
	}
}

func TestPKIFlowAndSiteAssignment(t *testing.T) {
	e := newEnv(t)
	c := e.login("admin")
	if code, _, _ := e.call("POST", "/api/pki/certs", map[string]any{"domain": "dev.local"}, c, nil); code != 400 {
		t.Fatalf("issue without any CA must fail, got %d", code)
	}
	code, ca1, _ := e.call("POST", "/api/pki/cas", map[string]any{"name": "CA One", "cn": "T CA", "years": 2}, c, nil)
	if code != 201 {
		t.Fatalf("CA: %d %v", code, ca1)
	}
	// второй CA — импортированный
	ext, extKey := externalCA(t)
	code, ca2, _ := e.call("POST", "/api/pki/cas/import", map[string]any{"name": "Corp", "cert": ext, "key": extKey}, c, nil)
	if code != 201 || ca2["imported"] != true {
		t.Fatalf("import: %d %v", code, ca2)
	}
	if code, _, _ := e.call("POST", "/api/pki/cas/import", map[string]any{"name": "dup", "cert": ext, "key": extKey}, c, nil); code != 400 {
		t.Errorf("duplicate import must fail, got %d", code)
	}
	code, list, _ := e.call("GET", "/api/pki", nil, c, nil)
	if code != 200 || len(list["cas"].([]any)) != 2 {
		t.Fatalf("expected two CAs: %v", list)
	}
	// при двух CA выбор обязателен
	if code, _, _ := e.call("POST", "/api/pki/certs", map[string]any{"domain": "dev.local"}, c, nil); code != 400 {
		t.Errorf("ambiguous CA must be rejected, got %d", code)
	}
	code, cert, _ := e.call("POST", "/api/pki/certs", map[string]any{"ca_id": ca2["id"], "domain": "dev.local", "days": 30}, c, nil)
	if code != 201 || cert["ca_id"] != ca2["id"] {
		t.Fatalf("issue: %d %v", code, cert)
	}
	serial := cert["serial"].(string)
	// CA с сертификатами удалить нельзя
	if code, _, _ := e.call("DELETE", "/api/pki/cas/"+ca2["id"].(string), nil, c, nil); code != 400 {
		t.Errorf("deleting a CA with certificates must fail, got %d", code)
	}
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
	e.call("DELETE", "/api/pki/certs/"+serial, nil, c, nil)
	if code, _, _ := e.call("DELETE", "/api/pki/cas/"+ca2["id"].(string), nil, c, nil); code != 200 {
		t.Errorf("deleting an empty CA: %d", code)
	}
	// viewer не может импортировать CA
	v := e.login("viewer")
	if code, _, _ := e.call("POST", "/api/pki/cas/import", map[string]any{"cert": ext, "key": extKey}, v, nil); code != 403 {
		t.Errorf("viewer import must be 403, got %d", code)
	}
}

// externalCA возвращает PEM сертификата и ключа CA, «выпущенного вне панели».
func externalCA(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Corp CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(3, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kd, _ := x509.MarshalPKCS8PrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}))
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

func TestUpdateAPI(t *testing.T) {
	e := newEnv(t)
	name := "goserverpanel-linux-" + runtime.GOARCH
	var base string
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases/latest":
			json.NewEncoder(w).Encode(map[string]any{"tag_name": "v99.0.0", "body": "n", "html_url": "http://x", "assets": []map[string]any{
				{"name": name, "browser_download_url": base + "/b"}, {"name": name + ".sha256", "browser_download_url": base + "/s"}}})
		default:
			w.Write([]byte("x"))
		}
	}))
	defer gh.Close()
	base = gh.URL
	exe := filepath.Join(t.TempDir(), "gsp")
	_ = os.WriteFile(exe, []byte("OLD"), 0o755)
	e.app.Upd.APIBase, e.app.Upd.Insecure, e.app.Upd.Exe, e.app.Upd.Repo = gh.URL, true, exe, "o/r"
	admin, viewer := e.login("admin"), e.login("viewer")

	for _, p := range []string{"/api/update", "/api/update/check", "/api/update/apply", "/api/update/rollback"} {
		m := "POST"
		if p == "/api/update" {
			m = "GET"
		}
		if code, _, _ := e.call(m, p, nil, viewer, nil); code != 403 {
			t.Errorf("viewer %s must be 403, got %d", p, code)
		}
		if code, _, _ := e.call(m, p, nil, nil, nil); code != 401 {
			t.Errorf("anonymous %s must be 401, got %d", p, code)
		}
	}
	code, body, _ := e.call("POST", "/api/update/check", nil, admin, nil)
	if code != 200 || body["available"] != true || body["latest"] != "99.0.0" {
		t.Fatalf("check: %d %v", code, body)
	}
	// dry_run: задача запускается, но бинарник не меняется и перезапуска нет
	if code, body, _ := e.call("POST", "/api/update/apply", nil, admin, nil); code != 200 && code != 202 || body["job"] == nil {
		t.Fatalf("apply: %d %v", code, body)
	}
	time.Sleep(300 * time.Millisecond)
	if b, _ := os.ReadFile(exe); string(b) != "OLD" {
		t.Error("dry-run apply must not modify the binary")
	}
	if code, _, _ := e.call("POST", "/api/update/rollback", nil, admin, nil); code != 400 {
		t.Errorf("rollback without backup must be 400, got %d", code)
	}
}

func TestSiteGate(t *testing.T) {
	e := newEnv(t)
	admin, viewer := e.login("admin"), e.login("viewer")

	// управление аккаунтами — только admin
	if code, _, _ := e.call("GET", "/api/siteusers", nil, viewer, nil); code != 403 {
		t.Errorf("viewer must not list site users: %d", code)
	}
	if code, _, _ := e.call("POST", "/api/siteusers", map[string]string{"username": "bob", "password": "short"}, admin, nil); code != 400 {
		t.Errorf("weak password must be rejected: %d", code)
	}
	code, body, _ := e.call("POST", "/api/siteusers", map[string]string{"username": "bob", "password": "bobs-password-1"}, admin, nil)
	if code != 201 || body["pass_hash"] != nil {
		t.Fatalf("create site user: %d %v", code, body)
	}
	bobID := body["id"].(string)
	if code, _, _ := e.call("POST", "/api/siteusers", map[string]string{"username": "BOB", "password": "another-pass-1"}, admin, nil); code != 409 {
		t.Errorf("duplicate (case-insensitive) must be 409, got %d", code)
	}

	// защищённый и обычный сайт
	code, site, _ := e.call("POST", "/api/sites", map[string]any{"domain": "closed.example.com", "protected": true}, admin, nil)
	if code != 201 {
		t.Fatalf("create protected site: %d %v", code, site)
	}
	if code, _, _ := e.call("POST", "/api/sites", map[string]any{"domain": "open.example.com"}, admin, nil); code != 201 {
		t.Fatal("create open site")
	}
	conf, _ := os.ReadFile(filepath.Join(e.cfg.NginxAvailable, "gsp-closed.example.com.conf"))
	if !strings.Contains(string(conf), "auth_request /_gsp/verify;") {
		t.Errorf("protected site config lacks auth_request:\n%s", conf)
	}
	if c, _ := os.ReadFile(filepath.Join(e.cfg.NginxAvailable, "gsp-open.example.com.conf")); strings.Contains(string(c), "auth_request") {
		t.Error("open site must not be protected")
	}

	gate := func(method, path, host string, form url.Values, cookie *http.Cookie) *http.Response {
		var rd io.Reader
		if form != nil {
			rd = strings.NewReader(form.Encode())
		}
		req, _ := http.NewRequest(method, e.srv.URL+path, rd)
		req.Header.Set("X-Gate-Host", host)
		req.Header.Set("X-Real-IP", "203.0.113.7")
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	login := func(user, pass, next string) *http.Response {
		return gate("POST", "/gate/login", "closed.example.com", url.Values{"username": {user}, "password": {pass}, "next": {next}}, nil)
	}

	if r := gate("GET", "/gate/verify", "closed.example.com", nil, nil); r.StatusCode != 401 {
		t.Errorf("verify without cookie: %d", r.StatusCode)
	}
	if r := gate("GET", "/gate/login", "closed.example.com", nil, nil); r.StatusCode != 200 {
		t.Errorf("login page: %d", r.StatusCode)
	}
	if r := gate("GET", "/gate/login", "open.example.com", nil, nil); r.StatusCode != 404 {
		t.Errorf("gate for unprotected site must be 404, got %d", r.StatusCode)
	}
	if r := login("bob", "wrong-password", "/"); r.StatusCode != 401 {
		t.Errorf("bad password: %d", r.StatusCode)
	}
	// open redirect исключён
	r := login("bob", "bobs-password-1", "//evil.example/x")
	if r.StatusCode != 303 || r.Header.Get("Location") != "/" {
		t.Fatalf("login: %d loc=%q", r.StatusCode, r.Header.Get("Location"))
	}
	var ck *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name == "gsp_gate" {
			ck = c
		}
	}
	if ck == nil || !ck.HttpOnly {
		t.Fatalf("gate cookie missing or not HttpOnly: %v", ck)
	}
	if r := login("BOB", "bobs-password-1", "/page?a=1&b=2"); r.Header.Get("Location") != "/page?a=1&b=2" {
		t.Errorf("next must be preserved, got %q", r.Header.Get("Location"))
	}
	if r := gate("GET", "/gate/verify", "closed.example.com", nil, ck); r.StatusCode != 200 {
		t.Errorf("verify with cookie: %d", r.StatusCode)
	}
	// токен привязан к сайту
	if r := gate("GET", "/gate/verify", "open.example.com", nil, ck); r.StatusCode != 401 {
		t.Errorf("cookie must not be valid for another site: %d", r.StatusCode)
	}
	// токен сайта не даёт доступа в панель
	if code, _, _ := e.call("GET", "/api/me", nil, &http.Cookie{Name: "gsp_session", Value: ck.Value}, nil); code != 401 {
		t.Errorf("gate token must not work as panel session: %d", code)
	}
	// смена пароля завершает сессии
	if code, _, _ := e.call("POST", "/api/siteusers/"+bobID+"/password", map[string]string{"password": "new-password-22"}, admin, nil); code != 200 {
		t.Fatal("change password")
	}
	if r := gate("GET", "/gate/verify", "closed.example.com", nil, ck); r.StatusCode != 401 {
		t.Errorf("session must end after password change: %d", r.StatusCode)
	}
	r = login("bob", "new-password-22", "/")
	for _, c := range r.Cookies() {
		if c.Name == "gsp_gate" {
			ck = c
		}
	}
	if r := gate("GET", "/gate/verify", "closed.example.com", nil, ck); r.StatusCode != 200 {
		t.Fatalf("verify after re-login: %d", r.StatusCode)
	}
	// удаление аккаунта закрывает доступ
	e.call("DELETE", "/api/siteusers/"+bobID, nil, admin, nil)
	if r := gate("GET", "/gate/verify", "closed.example.com", nil, ck); r.StatusCode != 401 {
		t.Errorf("deleted account must lose access: %d", r.StatusCode)
	}
	// перебор: после 5 неудач блокировка
	for i := 0; i < 5; i++ {
		login("nobody", "x", "/")
	}
	if r := login("nobody", "x", "/"); r.StatusCode != 429 {
		t.Errorf("gate login must be throttled, got %d", r.StatusCode)
	}
	// ручной конфиг и защита несовместимы
	id := site["id"].(string)
	if code, _, _ := e.call("PUT", "/api/sites/"+id+"/config", map[string]string{"config": "server {}"}, admin, nil); code != 400 {
		t.Errorf("raw config on protected site must be 400, got %d", code)
	}
	// маршруты /gate/ недоступны не с сервера
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/gate/login", nil)
	req.RemoteAddr = "198.51.100.9:5555"
	req.Header.Set("X-Gate-Host", "closed.example.com")
	e.app.Handler().ServeHTTP(rec, req)
	if rec.Code != 404 {
		t.Errorf("remote access to gate must be 404, got %d", rec.Code)
	}
}
