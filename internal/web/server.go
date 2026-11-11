// Package web: HTTP-роутер, middleware (IP-фильтр, аутентификация, CSRF, заголовки), API-контроллеры.
package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"goserverpanel/internal/auth"
	"goserverpanel/internal/config"
	"goserverpanel/internal/databases"
	"goserverpanel/internal/execx"
	"goserverpanel/internal/files"
	"goserverpanel/internal/jobs"
	"goserverpanel/internal/nginx"
	"goserverpanel/internal/php"
	"goserverpanel/internal/pki"
	"goserverpanel/internal/store"
	"goserverpanel/internal/system"
	"goserverpanel/internal/update"
	"goserverpanel/internal/ws"
)

type App struct {
	Cfg   *config.Config
	Store *store.Store
	Run   *execx.Runner
	Jobs  *jobs.Manager
	Nginx *nginx.Manager
	PHP   *php.Manager
	DB    *databases.Manager
	PKI   *pki.PKI
	Mon   *system.Monitor
	Files *files.Manager
	Upd   *update.Updater
	UI    fs.FS

	cidrs []*net.IPNet

	mu        sync.Mutex
	attempts  map[string]*attempt
	revoked   map[string]int64 // jti → exp
	termToken map[string]termGrant
}

type attempt struct {
	fails int
	until time.Time
}

type termGrant struct {
	userID string
	exp    time.Time
}

type ctxKey struct{}

func New(cfg *config.Config, st *store.Store, ui fs.FS) (*App, error) {
	run := &execx.Runner{DryRun: cfg.DryRun, Log: log.Printf}
	a := &App{
		Cfg: cfg, Store: st, Run: run, Jobs: jobs.New(), UI: ui,
		Nginx:     &nginx.Manager{Cfg: cfg, Run: run},
		PHP:       &php.Manager{Cfg: cfg, Run: run},
		DB:        &databases.Manager{Run: run, BackupDir: cfg.DataDir + "/backups"},
		PKI:       pki.New(cfg.DataDir),
		Mon:       system.NewMonitor(run, []string{"/", cfg.WWWRoot}),
		Files:     files.New(cfg.FilesRoots),
		Upd:       update.New(cfg.UpdateRepo, cfg.UpdateCheck),
		attempts:  map[string]*attempt{},
		revoked:   map[string]int64{},
		termToken: map[string]termGrant{},
	}
	for _, c := range cfg.AllowCIDRs {
		c = strings.TrimSpace(c)
		if !strings.Contains(c, "/") {
			if strings.Contains(c, ":") {
				c += "/128"
			} else {
				c += "/32"
			}
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("allow_cidrs: %w", err)
		}
		a.cidrs = append(a.cidrs, n)
	}
	return a, nil
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		fail(w, 400, "некорректный JSON: "+err.Error())
		return false
	}
	return true
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func (a *App) userFrom(r *http.Request) store.User {
	u, _ := r.Context().Value(ctxKey{}).(store.User)
	return u
}

func (a *App) audit(r *http.Request, action, detail string) {
	user := "-"
	if u := a.userFrom(r); u.Username != "" {
		user = u.Username
	}
	_ = a.Store.Update(func(d *store.Data) error {
		d.Audit = append(d.Audit, store.Audit{Time: time.Now(), User: user, IP: clientIP(r), Action: action, Detail: detail})
		return nil
	})
}

// ---------- middleware ----------

func (a *App) secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("panic: %v", rec)
				fail(w, 500, "внутренняя ошибка")
			}
		}()
		if strings.HasPrefix(r.URL.Path, "/gate/") {
			// только nginx с этого же сервера; ограничения IP панели к посетителям сайтов не относятся
			if !isLocal(clientIP(r)) {
				http.NotFound(w, r)
				return
			}
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "DENY")
			h.Set("Referrer-Policy", "same-origin")
			h.Set("Cache-Control", "no-store")
			h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
			next.ServeHTTP(w, r)
			return
		}
		if len(a.cidrs) > 0 {
			ip := net.ParseIP(clientIP(r))
			ok := false
			for _, n := range a.cidrs {
				if ip != nil && n.Contains(ip) {
					ok = true
					break
				}
			}
			if !ok {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

const (
	lvlAny   = 0 // любой вошедший пользователь
	lvlWrite = 1 // чтение — всем, изменения — только admin
	lvlAdmin = 2 // только admin
)

func (a *App) authenticate(r *http.Request) (store.User, auth.Claims, bool, bool) {
	var tok string
	viaCookie := false
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		tok = strings.TrimPrefix(h, "Bearer ")
	} else if c, err := r.Cookie("gsp_session"); err == nil {
		tok, viaCookie = c.Value, true
	}
	if tok == "" {
		return store.User{}, auth.Claims{}, false, false
	}
	var secret string
	a.Store.View(func(d *store.Data) { secret = d.JWTSecret })
	cl, err := auth.VerifyJWT([]byte(secret), tok)
	if err != nil {
		return store.User{}, cl, false, false
	}
	a.mu.Lock()
	_, rev := a.revoked[cl.JTI]
	a.mu.Unlock()
	if rev {
		return store.User{}, cl, false, false
	}
	var u store.User
	found := false
	a.Store.View(func(d *store.Data) {
		for _, x := range d.Users {
			if x.ID == cl.Sub {
				u, found = x, true
			}
		}
	})
	return u, cl, found, viaCookie
}

func (a *App) guard(level int, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, _, ok, viaCookie := a.authenticate(r)
		if !ok {
			fail(w, 401, "требуется вход")
			return
		}
		mut := r.Method != http.MethodGet && r.Method != http.MethodHead
		if mut && viaCookie && r.Header.Get("X-Requested-With") != "gsp" {
			fail(w, 403, "отсутствует CSRF-заголовок")
			return
		}
		if u.Role != "admin" && (level == lvlAdmin || (level == lvlWrite && mut)) {
			fail(w, 403, "недостаточно прав")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	}
}

// ---------- throttle ----------

func (a *App) locked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	at := a.attempts[ip]
	return at != nil && time.Now().Before(at.until)
}

func (a *App) recordFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.attempts) > 10000 {
		a.attempts = map[string]*attempt{}
	}
	at := a.attempts[ip]
	if at == nil {
		at = &attempt{}
		a.attempts[ip] = at
	}
	if at.fails++; at.fails >= 5 {
		at.until, at.fails = time.Now().Add(5*time.Minute), 0
	}
}

func (a *App) clearFails(ip string) {
	a.mu.Lock()
	delete(a.attempts, ip)
	a.mu.Unlock()
}

// ---------- routing ----------

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	r := func(pattern string, level int, h http.HandlerFunc) { mux.HandleFunc(pattern, a.guard(level, h)) }

	mux.HandleFunc("POST /api/login", a.handleLogin)
	r("POST /api/logout", lvlAny, a.handleLogout)
	r("GET /api/me", lvlAny, a.handleMe)
	r("POST /api/me/password", lvlAny, a.handlePassword)
	r("POST /api/me/2fa/setup", lvlAny, a.handle2FASetup)
	r("POST /api/me/2fa/enable", lvlAny, a.handle2FAEnable)
	r("POST /api/me/2fa/disable", lvlAny, a.handle2FADisable)
	r("GET /api/users", lvlAdmin, a.handleUsers)
	r("POST /api/users", lvlAdmin, a.handleUserCreate)
	r("DELETE /api/users/{id}", lvlAdmin, a.handleUserDelete)
	r("GET /api/audit", lvlAdmin, a.handleAudit)

	r("GET /api/update", lvlAdmin, a.handleUpdateInfo)
	r("POST /api/update/check", lvlAdmin, a.handleUpdateCheck)
	r("POST /api/update/apply", lvlAdmin, a.handleUpdateApply)
	r("POST /api/update/rollback", lvlAdmin, a.handleUpdateRollback)

	r("GET /api/siteusers", lvlAdmin, a.handleSiteUsers)
	r("POST /api/siteusers", lvlAdmin, a.handleSiteUserCreate)
	r("POST /api/siteusers/{id}/password", lvlAdmin, a.handleSiteUserPassword)
	r("DELETE /api/siteusers/{id}", lvlAdmin, a.handleSiteUserDelete)
	mux.HandleFunc("GET /gate/verify", a.gateOnly(a.handleGateVerify))
	mux.HandleFunc("GET /gate/login", a.gateOnly(a.handleGateLoginPage))
	mux.HandleFunc("POST /gate/login", a.gateOnly(a.handleGateLogin))
	mux.HandleFunc("GET /gate/logout", a.gateOnly(a.handleGateLogout))
	r("GET /api/stats", lvlAny, a.handleStats)
	r("GET /api/ws/stats", lvlAny, a.handleStatsWS)
	r("GET /api/services", lvlAny, a.handleServices)
	r("POST /api/services/{name}/{action}", lvlWrite, a.handleServiceAction)
	r("GET /api/jobs/{id}", lvlAny, a.handleJob)
	r("GET /api/jobs/{id}/ws", lvlAny, a.handleJobWS)

	r("GET /api/sites", lvlAny, a.handleSites)
	r("POST /api/sites", lvlWrite, a.handleSiteCreate)
	r("GET /api/sites/{id}", lvlAny, a.handleSiteGet)
	r("PUT /api/sites/{id}", lvlWrite, a.handleSiteUpdate)
	r("DELETE /api/sites/{id}", lvlWrite, a.handleSiteDelete)
	r("GET /api/sites/{id}/config", lvlAny, a.handleSiteConfigGet)
	r("PUT /api/sites/{id}/config", lvlWrite, a.handleSiteConfigPut)
	r("GET /api/sites/{id}/logs", lvlAdmin, a.handleSiteLogs)
	r("GET /api/nginx", lvlAny, a.handleNginxStatus)
	r("POST /api/nginx/install", lvlWrite, a.handleNginxInstall)
	r("POST /api/nginx/test", lvlWrite, a.handleNginxTest)
	r("POST /api/nginx/reload", lvlWrite, a.handleNginxReload)

	r("GET /api/php", lvlAny, a.handlePHPVersions)
	r("POST /api/php/{ver}/install", lvlWrite, a.handlePHPInstall)
	r("GET /api/php/{ver}/modules", lvlAny, a.handlePHPModules)
	r("POST /api/php/{ver}/modules/{name}/{action}", lvlWrite, a.handlePHPModuleAction)
	r("GET /api/php/{ver}/ini", lvlAny, a.handlePHPIniGet)
	r("PUT /api/php/{ver}/ini", lvlWrite, a.handlePHPIniPut)

	r("GET /api/db", lvlAny, a.handleDBStatus)
	r("GET /api/dbbackups", lvlAdmin, a.handleDBBackups)
	r("GET /api/dbbackups/{file}", lvlAdmin, a.handleDBBackupDownload)
	r("POST /api/db/{engine}/install", lvlWrite, a.handleDBInstall)
	r("GET /api/db/{engine}/databases", lvlAny, a.handleDBList)
	r("POST /api/db/{engine}/databases", lvlWrite, a.handleDBCreate)
	r("DELETE /api/db/{engine}/databases/{name}", lvlWrite, a.handleDBDrop)
	r("POST /api/db/{engine}/databases/{name}/backup", lvlWrite, a.handleDBBackup)
	r("POST /api/db/{engine}/databases/{name}/restore", lvlWrite, a.handleDBRestore)
	r("GET /api/db/{engine}/users", lvlAny, a.handleDBUsers)
	r("POST /api/db/{engine}/users", lvlWrite, a.handleDBUserCreate)
	r("DELETE /api/db/{engine}/users/{name}", lvlWrite, a.handleDBUserDrop)
	r("POST /api/db/{engine}/grant", lvlWrite, a.handleDBGrant)

	r("GET /api/cms", lvlAny, a.handleCMSCatalog)
	r("POST /api/cms/install", lvlWrite, a.handleCMSInstall)

	r("GET /api/pki", lvlAny, a.handlePKI)
	r("POST /api/pki/cas", lvlWrite, a.handlePKICreateCA)
	r("POST /api/pki/cas/import", lvlWrite, a.handlePKIImportCA)
	r("DELETE /api/pki/cas/{id}", lvlWrite, a.handlePKIDeleteCA)
	r("GET /api/pki/cas/{id}/ca.crt", lvlAny, a.handlePKICACert)
	r("GET /api/pki/cas/{id}/crl", lvlAny, a.handlePKICRL)
	r("POST /api/pki/certs", lvlWrite, a.handlePKIIssue)
	r("GET /api/pki/certs/{serial}/download", lvlAny, a.handlePKICertDownload)
	r("POST /api/pki/certs/{serial}/revoke", lvlWrite, a.handlePKIRevoke)
	r("DELETE /api/pki/certs/{serial}", lvlWrite, a.handlePKIDelete)

	r("POST /api/terminal/token", lvlAdmin, a.handleTerminalToken)
	r("GET /api/terminal/ws", lvlAdmin, a.handleTerminalWS)

	r("GET /api/files", lvlAdmin, a.handleFilesList)
	r("GET /api/files/read", lvlAdmin, a.handleFilesRead)
	r("PUT /api/files/write", lvlAdmin, a.handleFilesWrite)
	r("POST /api/files/mkdir", lvlAdmin, a.handleFilesMkdir)
	r("POST /api/files/rename", lvlAdmin, a.handleFilesRename)
	r("DELETE /api/files", lvlAdmin, a.handleFilesDelete)
	r("POST /api/files/upload", lvlAdmin, a.handleFilesUpload)
	r("GET /api/files/download", lvlAdmin, a.handleFilesDownload)

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { fail(w, 404, "не найдено") })
	mux.Handle("/", http.FileServer(http.FS(a.UI)))
	return a.secure(mux)
}

// ---------- WebSocket-помощники ----------

// watchClose читает входящие кадры (ответы на ping, закрытие) и вызывает onClose при разрыве.
func watchClose(c *ws.Conn, onClose func()) {
	go func() {
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				onClose()
				return
			}
		}
	}()
}

var _ = regexp.MustCompile
