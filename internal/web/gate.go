package web

import (
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"goserverpanel/internal/auth"
	"goserverpanel/internal/store"
)

// Общая авторизация сайтов. nginx защищённого сайта делает auth_request на /gate/verify панели
// и проксирует /_gsp/* на /gate/*. Эти маршруты доступны только с самого сервера (nginx → панель).

const gateCookie = "gsp_gate"

// isLocal: запрос пришёл с этого же сервера (loopback или адрес одного из интерфейсов).
func isLocal(remote string) bool {
	ip := net.ParseIP(remote)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	addrs, _ := net.InterfaceAddrs()
	for _, ad := range addrs {
		if n, ok := ad.(*net.IPNet); ok && n.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// gateKey — отдельный ключ для токенов входа на сайты: токен сайта не подходит как сессия панели.
func (a *App) gateKey() []byte {
	var secret string
	a.Store.View(func(d *store.Data) { secret = d.JWTSecret })
	sum := sha256.Sum256([]byte("gsp-gate|" + secret))
	return sum[:]
}

// passFingerprint привязывает сессию к текущему паролю: смена пароля завершает старые сессии.
func passFingerprint(hash string) string {
	sum := sha256.Sum256([]byte(hash))
	return hex.EncodeToString(sum[:6])
}

func (a *App) gateSite(r *http.Request) (store.Site, bool) {
	host := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Gate-Host")))
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host, "]") {
		host = host[:i]
	}
	var out store.Site
	var ok bool
	a.Store.View(func(d *store.Data) {
		for _, s := range d.Sites {
			if !s.Protected || !s.Enabled {
				continue
			}
			if s.Domain == host {
				out, ok = s, true
				return
			}
			for _, al := range s.Aliases {
				if al == host {
					out, ok = s, true
					return
				}
			}
		}
	})
	return out, ok
}

func realIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(v) != nil {
		return v
	}
	return clientIP(r)
}

func (a *App) auditAs(user, ip, action, detail string) {
	_ = a.Store.Update(func(d *store.Data) error {
		d.Audit = append(d.Audit, store.Audit{Time: time.Now(), User: user, IP: ip, Action: action, Detail: detail})
		return nil
	})
}

// gateOnly пропускает только запросы с этого сервера.
func (a *App) gateOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isLocal(clientIP(r)) {
			http.NotFound(w, r)
			return
		}
		h(w, r)
	}
}

func (a *App) handleGateVerify(w http.ResponseWriter, r *http.Request) {
	site, ok := a.gateSite(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	c, err := r.Cookie(gateCookie)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	cl, err := auth.VerifyJWT(a.gateKey(), c.Value)
	if err != nil || cl.Name != site.ID {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	valid := false
	a.Store.View(func(d *store.Data) {
		for _, u := range d.SiteUsers {
			if u.ID == cl.Sub && cl.Role == "g"+passFingerprint(u.PassHash) {
				valid = true
			}
		}
	})
	if !valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// gateNext допускает только локальный путь (защита от open redirect).
var nextRe = regexp.MustCompile("^/[^\\s\\\\<>\"'`]*$")

func gateNext(s string) string {
	if len(s) > 2000 || !nextRe.MatchString(s) || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/_gsp/") {
		return "/"
	}
	return s
}

// nginx передаёт исходный адрес как есть (без кодирования), поэтому берём всё после "next=".
func nextFromQuery(r *http.Request) string {
	raw := r.URL.RawQuery
	if strings.HasPrefix(raw, "next=") {
		return gateNext(raw[5:])
	}
	return gateNext(r.URL.Query().Get("next"))
}

var loginTpl = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Вход — {{.Domain}}</title>
<style>
:root{color-scheme:light dark;--bg:#f4f6fb;--card:#fff;--fg:#1c2433;--mut:#6b7587;--bd:#dde2ee;--ac:#3b6ef6;--err:#d93f4c}
@media(prefers-color-scheme:dark){:root{--bg:#10141d;--card:#181d29;--fg:#e6eaf3;--mut:#93a0b8;--bd:#283044;--ac:#6b93ff;--err:#ff6b78}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
form{width:min(380px,92vw);background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:28px;box-shadow:0 10px 30px rgba(0,0,0,.08)}
h1{margin:0 0 4px;font-size:20px}p{margin:0 0 18px;color:var(--mut);font-size:14px}
label{display:block;margin-bottom:12px;font-size:13px;color:var(--mut)}
input{width:100%;margin-top:4px;padding:10px 12px;border:1px solid var(--bd);border-radius:8px;background:transparent;color:var(--fg);font:inherit}
input:focus{outline:2px solid var(--ac);outline-offset:-1px}
button{width:100%;margin-top:6px;padding:11px;border:0;border-radius:8px;background:var(--ac);color:#fff;font:inherit;font-weight:600;cursor:pointer}
.err{margin-bottom:12px;padding:9px 12px;border-radius:8px;border:1px solid var(--err);color:var(--err);font-size:13px}
</style></head><body>
<form method="post" action="/_gsp/login" autocomplete="on">
<h1>Закрытый доступ</h1><p>{{.Domain}}</p>
{{if .Error}}<div class="err">{{.Error}}</div>{{end}}
<input type="hidden" name="next" value="{{.Next}}">
<label>Логин<input name="username" autocomplete="username" autofocus required maxlength="64"></label>
<label>Пароль<input name="password" type="password" autocomplete="current-password" required maxlength="256"></label>
<button type="submit">Войти</button>
</form></body></html>`))

func (a *App) renderLogin(w http.ResponseWriter, code int, site store.Site, next, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_ = loginTpl.Execute(w, map[string]string{"Domain": site.Domain, "Next": next, "Error": errMsg})
}

func (a *App) handleGateLoginPage(w http.ResponseWriter, r *http.Request) {
	site, ok := a.gateSite(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	a.renderLogin(w, 200, site, nextFromQuery(r), "")
}

func (a *App) handleGateLogin(w http.ResponseWriter, r *http.Request) {
	site, ok := a.gateSite(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ip := realIP(r)
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	next := gateNext(r.PostForm.Get("next"))
	key := "gate|" + ip
	if a.locked(key) {
		a.renderLogin(w, 429, site, next, "Слишком много попыток. Повторите через 5 минут.")
		return
	}
	name, pass := strings.TrimSpace(r.PostForm.Get("username")), r.PostForm.Get("password")
	var su store.SiteUser
	found := false
	a.Store.View(func(d *store.Data) {
		for _, u := range d.SiteUsers {
			if strings.EqualFold(u.Username, name) {
				su, found = u, true
			}
		}
	})
	if !found {
		auth.DummyVerify()
	}
	if !found || !auth.VerifyPassword(pass, su.PassHash) {
		a.recordFail(key)
		a.auditAs(name, ip, "gate.fail", site.Domain)
		a.renderLogin(w, 401, site, next, "Неверный логин или пароль.")
		return
	}
	a.clearFails(key)
	exp := time.Now().Add(time.Duration(a.Cfg.SessionHours) * time.Hour)
	tok := auth.SignJWT(a.gateKey(), auth.Claims{Sub: su.ID, Name: site.ID, Role: "g" + passFingerprint(su.PassHash), Exp: exp.Unix(), JTI: auth.RandomString(12)})
	http.SetCookie(w, &http.Cookie{Name: gateCookie, Value: tok, Path: "/", Expires: exp, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: r.Header.Get("X-Forwarded-Proto") == "https"})
	a.auditAs(su.Username, ip, "gate.login", site.Domain)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (a *App) handleGateLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: gateCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: r.Header.Get("X-Forwarded-Proto") == "https"})
	http.Redirect(w, r, "/_gsp/login", http.StatusSeeOther)
}

// ---------- управление аккаунтами (панель) ----------

type siteUserView struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Created  time.Time `json:"created"`
}

func (a *App) handleSiteUsers(w http.ResponseWriter, r *http.Request) {
	out := []siteUserView{}
	a.Store.View(func(d *store.Data) {
		for _, u := range d.SiteUsers {
			out = append(out, siteUserView{u.ID, u.Username, u.Created})
		}
	})
	writeJSON(w, 200, out)
}

func (a *App) handleSiteUserCreate(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if !decode(w, r, &in) {
		return
	}
	if !usernameRe.MatchString(in.Username) {
		fail(w, 400, "логин: 3–32 символа (латиница, цифры, _ . -)")
		return
	}
	if len(in.Password) < 8 || len(in.Password) > 128 {
		fail(w, 400, "пароль: от 8 до 128 символов")
		return
	}
	h, err := auth.HashPassword(in.Password)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	u := store.SiteUser{ID: store.NewID(), Username: in.Username, PassHash: h, Created: time.Now()}
	err = a.Store.Update(func(d *store.Data) error {
		for _, x := range d.SiteUsers {
			if strings.EqualFold(x.Username, in.Username) {
				return http.ErrNotSupported
			}
		}
		d.SiteUsers = append(d.SiteUsers, u)
		return nil
	})
	if err != nil {
		fail(w, 409, "аккаунт уже существует")
		return
	}
	a.audit(r, "siteuser.create", in.Username)
	writeJSON(w, 201, siteUserView{u.ID, u.Username, u.Created})
}

func (a *App) handleSiteUserPassword(w http.ResponseWriter, r *http.Request) {
	var in struct{ Password string }
	if !decode(w, r, &in) {
		return
	}
	if len(in.Password) < 8 || len(in.Password) > 128 {
		fail(w, 400, "пароль: от 8 до 128 символов")
		return
	}
	h, err := auth.HashPassword(in.Password)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	var name string
	err = a.Store.Update(func(d *store.Data) error {
		for i := range d.SiteUsers {
			if d.SiteUsers[i].ID == r.PathValue("id") {
				d.SiteUsers[i].PassHash, name = h, d.SiteUsers[i].Username
				return nil
			}
		}
		return http.ErrMissingFile
	})
	if err != nil {
		fail(w, 404, "аккаунт не найден")
		return
	}
	a.audit(r, "siteuser.password", name)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleSiteUserDelete(w http.ResponseWriter, r *http.Request) {
	var name string
	err := a.Store.Update(func(d *store.Data) error {
		for i, x := range d.SiteUsers {
			if x.ID == r.PathValue("id") {
				name = x.Username
				d.SiteUsers = append(d.SiteUsers[:i], d.SiteUsers[i+1:]...)
				return nil
			}
		}
		return http.ErrMissingFile
	})
	if err != nil {
		fail(w, 404, "аккаунт не найден")
		return
	}
	a.audit(r, "siteuser.delete", name)
	writeJSON(w, 200, map[string]any{"ok": true})
}
