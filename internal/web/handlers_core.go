package web

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"goserverpanel/internal/auth"
	"goserverpanel/internal/store"
	"goserverpanel/internal/ws"
)

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{3,32}$`)

func (a *App) findUserByName(name string) (u store.User, ok bool) {
	a.Store.View(func(d *store.Data) {
		for _, x := range d.Users {
			if strings.EqualFold(x.Username, name) {
				u, ok = x, true
			}
		}
	})
	return
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if a.locked(ip) {
		fail(w, 429, "слишком много попыток входа, повторите через 5 минут")
		return
	}
	var in struct{ Username, Password, TOTP string }
	if !decode(w, r, &in) {
		return
	}
	u, ok := a.findUserByName(in.Username)
	if !ok {
		auth.DummyVerify()
		a.recordFail(ip)
		a.audit(r, "login.fail", in.Username)
		fail(w, 401, "неверный логин или пароль")
		return
	}
	if !auth.VerifyPassword(in.Password, u.PassHash) {
		a.recordFail(ip)
		a.audit(r, "login.fail", in.Username)
		fail(w, 401, "неверный логин или пароль")
		return
	}
	if u.TOTPEnabled {
		if in.TOTP == "" {
			writeJSON(w, 401, map[string]any{"error": "введите код двухфакторной аутентификации", "need_totp": true})
			return
		}
		if !auth.VerifyTOTP(u.TOTPSecret, in.TOTP, time.Now()) {
			a.recordFail(ip)
			a.audit(r, "login.fail", in.Username+" (2FA)")
			fail(w, 401, "неверный код 2FA")
			return
		}
	}
	a.clearFails(ip)
	var secret string
	a.Store.View(func(d *store.Data) { secret = d.JWTSecret })
	exp := time.Now().Add(time.Duration(a.Cfg.SessionHours) * time.Hour)
	tok := auth.SignJWT([]byte(secret), auth.Claims{Sub: u.ID, Name: u.Username, Role: u.Role, Exp: exp.Unix(), JTI: auth.RandomString(16)})
	http.SetCookie(w, &http.Cookie{Name: "gsp_session", Value: tok, Path: "/", Expires: exp, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, u))
	a.audit(r, "login", "")
	writeJSON(w, 200, map[string]any{"user": u})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if _, cl, ok, _ := a.authenticate(r); ok {
		a.mu.Lock()
		a.revoked[cl.JTI] = cl.Exp
		now := time.Now().Unix()
		for k, e := range a.revoked {
			if e < now {
				delete(a.revoked, k)
			}
		}
		a.mu.Unlock()
	}
	a.audit(r, "logout", "")
	http.SetCookie(w, &http.Cookie{Name: "gsp_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) {
	_, xerr := fs.Stat(a.UI, "vendor/xterm.js")
	writeJSON(w, 200, map[string]any{"user": a.userFrom(r), "dry_run": a.Cfg.DryRun, "terminal_enabled": a.Cfg.TerminalEnabled, "xterm": xerr == nil})
}

func (a *App) setUser(id string, fn func(u *store.User) error) error {
	return a.Store.Update(func(d *store.Data) error {
		for i := range d.Users {
			if d.Users[i].ID == id {
				return fn(&d.Users[i])
			}
		}
		return http.ErrMissingFile
	})
}

func (a *App) handlePassword(w http.ResponseWriter, r *http.Request) {
	u := a.userFrom(r)
	var in struct{ Old, New string }
	if !decode(w, r, &in) {
		return
	}
	if !auth.VerifyPassword(in.Old, u.PassHash) {
		fail(w, 403, "текущий пароль неверен")
		return
	}
	if len(in.New) < 10 || len(in.New) > 128 {
		fail(w, 400, "новый пароль: от 10 до 128 символов")
		return
	}
	h, err := auth.HashPassword(in.New)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	if err := a.setUser(u.ID, func(x *store.User) error { x.PassHash = h; return nil }); err != nil {
		fail(w, 500, err.Error())
		return
	}
	a.audit(r, "password.change", "")
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handle2FASetup(w http.ResponseWriter, r *http.Request) {
	u := a.userFrom(r)
	if u.TOTPEnabled {
		fail(w, 400, "2FA уже включена")
		return
	}
	secret := auth.NewTOTPSecret()
	if err := a.setUser(u.ID, func(x *store.User) error { x.TOTPSecret = secret; return nil }); err != nil {
		fail(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"secret": secret, "uri": auth.TOTPURI("GoServerPanel", u.Username, secret)})
}

func (a *App) handle2FAEnable(w http.ResponseWriter, r *http.Request) {
	u := a.userFrom(r)
	var in struct{ Code string }
	if !decode(w, r, &in) {
		return
	}
	if u.TOTPSecret == "" || !auth.VerifyTOTP(u.TOTPSecret, in.Code, time.Now()) {
		fail(w, 400, "неверный код")
		return
	}
	_ = a.setUser(u.ID, func(x *store.User) error { x.TOTPEnabled = true; return nil })
	a.audit(r, "2fa.enable", "")
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handle2FADisable(w http.ResponseWriter, r *http.Request) {
	u := a.userFrom(r)
	var in struct{ Password, Code string }
	if !decode(w, r, &in) {
		return
	}
	if !auth.VerifyPassword(in.Password, u.PassHash) || !u.TOTPEnabled || !auth.VerifyTOTP(u.TOTPSecret, in.Code, time.Now()) {
		fail(w, 403, "неверный пароль или код")
		return
	}
	_ = a.setUser(u.ID, func(x *store.User) error { x.TOTPEnabled, x.TOTPSecret = false, ""; return nil })
	a.audit(r, "2fa.disable", "")
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleUsers(w http.ResponseWriter, r *http.Request) {
	var list []store.User
	a.Store.View(func(d *store.Data) { list = append(list, d.Users...) })
	writeJSON(w, 200, list)
}

func (a *App) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password, Role string }
	if !decode(w, r, &in) {
		return
	}
	if !usernameRe.MatchString(in.Username) {
		fail(w, 400, "логин: 3–32 символа (латиница, цифры, _ . -)")
		return
	}
	if len(in.Password) < 10 || len(in.Password) > 128 {
		fail(w, 400, "пароль: от 10 до 128 символов")
		return
	}
	if in.Role != "admin" && in.Role != "viewer" {
		fail(w, 400, "роль: admin или viewer")
		return
	}
	h, err := auth.HashPassword(in.Password)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	u := store.User{ID: store.NewID(), Username: in.Username, PassHash: h, Role: in.Role, Created: time.Now()}
	err = a.Store.Update(func(d *store.Data) error {
		for _, x := range d.Users {
			if strings.EqualFold(x.Username, in.Username) {
				return http.ErrNotSupported
			}
		}
		d.Users = append(d.Users, u)
		return nil
	})
	if err != nil {
		fail(w, 409, "пользователь уже существует")
		return
	}
	a.audit(r, "user.create", in.Username+" ("+in.Role+")")
	writeJSON(w, 201, u)
}

func (a *App) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	me := a.userFrom(r)
	if id == me.ID {
		fail(w, 400, "нельзя удалить самого себя")
		return
	}
	var name string
	err := a.Store.Update(func(d *store.Data) error {
		for i, x := range d.Users {
			if x.ID == id {
				name = x.Username
				d.Users = append(d.Users[:i], d.Users[i+1:]...)
				return nil
			}
		}
		return http.ErrMissingFile
	})
	if err != nil {
		fail(w, 404, "пользователь не найден")
		return
	}
	a.audit(r, "user.delete", name)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleAudit(w http.ResponseWriter, r *http.Request) {
	var out []store.Audit
	a.Store.View(func(d *store.Data) {
		n := len(d.Audit)
		for i := n - 1; i >= 0 && len(out) < 300; i-- {
			out = append(out, d.Audit[i])
		}
	})
	writeJSON(w, 200, out)
}

// ---------- система ----------

func (a *App) handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.Mon.Snapshot())
}

func (a *App) handleStatsWS(w http.ResponseWriter, r *http.Request) {
	c, err := ws.Accept(w, r)
	if err != nil {
		return
	}
	defer c.Close()
	stop := make(chan struct{})
	watchClose(c, func() { close(stop) })
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		b, _ := json.Marshal(a.Mon.Snapshot())
		if c.WriteText(string(b)) != nil {
			return
		}
		select {
		case <-stop:
			return
		case <-t.C:
		}
	}
}

func (a *App) serviceNames() []string {
	names := []string{"nginx", "mysql", "mariadb", "postgresql", "redis-server"}
	for _, v := range a.PHP.Versions() {
		if v.Installed {
			names = append(names, v.Service)
		}
	}
	sort.Strings(names)
	return names
}

func (a *App) handleServices(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.Mon.Services(r.Context(), a.serviceNames()))
}

func (a *App) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	name, action := r.PathValue("name"), r.PathValue("action")
	out, err := a.Mon.ServiceAction(r.Context(), name, action)
	a.audit(r, "service."+action, name)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "output": out})
}

// ---------- задачи ----------

func (a *App) handleJob(w http.ResponseWriter, r *http.Request) {
	j := a.Jobs.Get(r.PathValue("id"))
	if j == nil {
		fail(w, 404, "задача не найдена")
		return
	}
	writeJSON(w, 200, j.View())
}

func (a *App) handleJobWS(w http.ResponseWriter, r *http.Request) {
	j := a.Jobs.Get(r.PathValue("id"))
	if j == nil {
		fail(w, 404, "задача не найдена")
		return
	}
	c, err := ws.Accept(w, r)
	if err != nil {
		return
	}
	defer c.Close()
	initial, ch, cancel, done := j.Subscribe()
	defer cancel()
	closed := make(chan struct{})
	watchClose(c, func() { close(closed) })
	if len(initial) > 0 && c.WriteMessage(ws.OpText, initial) != nil {
		return
	}
	for {
		select {
		case chunk := <-ch:
			if c.WriteMessage(ws.OpText, chunk) != nil {
				return
			}
		case <-done:
			for {
				select {
				case chunk := <-ch:
					_ = c.WriteMessage(ws.OpText, chunk)
				default:
					return
				}
			}
		case <-closed:
			return
		}
	}
}
