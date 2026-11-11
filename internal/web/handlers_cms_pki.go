package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"goserverpanel/internal/databases"
	"goserverpanel/internal/installer"
	"goserverpanel/internal/nginx"
	"goserverpanel/internal/store"
)

func (a *App) handleCMSCatalog(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, installer.Catalog())
}

var nonIdent = regexp.MustCompile(`[^a-z0-9]+`)

func dbIdent(prefix, domain string) string {
	b := make([]byte, 2)
	_, _ = rand.Read(b)
	base := strings.Trim(nonIdent.ReplaceAllString(strings.ToLower(domain), "_"), "_")
	if len(base) > 32-len(prefix)-5 {
		base = base[:32-len(prefix)-5]
	}
	return fmt.Sprintf("%s%s_%s", prefix, base, hex.EncodeToString(b))
}

type cmsReq struct {
	CMS        string   `json:"cms"`
	Domain     string   `json:"domain"`
	Aliases    []string `json:"aliases"`
	PHPVersion string   `json:"php_version"`
	DBEngine   string   `json:"db_engine"`
}

func (a *App) handleCMSInstall(w http.ResponseWriter, r *http.Request) {
	var in cmsReq
	if !decode(w, r, &in) {
		return
	}
	app, ok := installer.Find(in.CMS)
	if !ok {
		fail(w, 400, "неизвестная CMS")
		return
	}
	probe := store.Site{Domain: in.Domain, Aliases: in.Aliases, PHPVersion: in.PHPVersion}
	if err := nginx.Validate(&probe, a.Cfg.WWWRoot); err != nil {
		// Validate требует root/proxy — для предварительной проверки домена подставим фиктивный корень
		probe.Root = filepath.Join(a.Cfg.WWWRoot, probe.Domain, "x")
		if err2 := nginx.Validate(&probe, a.Cfg.WWWRoot); err2 != nil {
			fail(w, 400, err2.Error())
			return
		}
	}
	if app.NeedsPHP && in.PHPVersion == "" {
		fail(w, 400, "выберите версию PHP")
		return
	}
	engine := in.DBEngine
	if engine == "" {
		engine = databases.MySQL
	}
	if app.ID == "wordpress" && engine != databases.MySQL {
		fail(w, 400, "WordPress поддерживает только MySQL/MariaDB")
		return
	}
	if app.ID == "laravel" {
		engine = "" // БД настраивается в .env вручную
	}
	if err := a.checkSiteRefs(&probe, ""); err != nil {
		fail(w, 400, err.Error())
		return
	}
	domain := probe.Domain
	dir := filepath.Join(a.Cfg.WWWRoot, domain, "public_html")
	if app.ID == "laravel" {
		dir = filepath.Join(a.Cfg.WWWRoot, domain, "app")
	}
	if ents, err := os.ReadDir(dir); err == nil && len(ents) > 0 {
		fail(w, 400, "каталог "+dir+" не пуст")
		return
	}

	j := a.Jobs.Start("Установка "+app.Name+" на "+domain, func(ctx context.Context, w io.Writer) (err error) {
		var dbName, dbUser, dbPass string
		dirCreated := false
		if _, serr := os.Stat(dir); os.IsNotExist(serr) {
			dirCreated = true
		}
		dbDone := false
		defer func() {
			if err == nil {
				return
			}
			fmt.Fprintln(w, "↩ Откатываю изменения")
			if dbDone {
				_ = a.DB.DropDatabase(ctx, engine, dbName)
				_ = a.DB.DropUser(ctx, engine, dbUser)
			}
			if dirCreated && !a.Cfg.DryRun {
				_ = os.RemoveAll(filepath.Join(a.Cfg.WWWRoot, domain))
			}
		}()

		if engine != "" {
			dbName, dbUser, dbPass = dbIdent("db_", domain), dbIdent("u_", domain), databases.GeneratePassword()
			fmt.Fprintf(w, "→ Создаю базу данных %s и пользователя %s\n", dbName, dbUser)
			if err = a.DB.CreateUser(ctx, engine, dbUser, dbPass); err != nil {
				return err
			}
			dbDone = true
			if err = a.DB.CreateDatabase(ctx, engine, dbName, "utf8mb4_unicode_ci", dbUser); err != nil {
				return err
			}
			if err = a.DB.Grant(ctx, engine, dbName, dbUser); err != nil {
				return err
			}
		}
		host := "localhost"
		if err = installer.Install(ctx, w, a.Run, installer.Params{
			App: app, Dir: dir, DBName: dbName, DBUser: dbUser, DBPass: dbPass, DBHost: host,
			WebUser: a.Cfg.WebUser, PHPVersion: in.PHPVersion,
		}); err != nil {
			return err
		}

		root := dir
		if app.WebSubdir != "" {
			root = filepath.Join(dir, app.WebSubdir)
		}
		site := store.Site{Domain: domain, Aliases: in.Aliases, Root: root, PHPVersion: in.PHPVersion, CMS: app.ID, Cache: true, MaxBody: "64m"}
		fmt.Fprintln(w, "→ Создаю виртуальный хост nginx")
		if err = a.createSite(ctx, &site); err != nil {
			return err
		}

		fmt.Fprintf(w, "\n══ Установка завершена ══\nАдрес мастера настройки: http://%s%s\n", domain, app.Post)
		if engine != "" {
			fmt.Fprintf(w, "База данных (%s): %s\nПользователь:  %s\nПароль:        %s\nХост:          %s\n", engine, dbName, dbUser, dbPass, host)
			if !app.AutoConfig {
				fmt.Fprintln(w, "Эти данные понадобятся в мастере установки CMS — сохраните их сейчас.")
			}
		}
		return nil
	})
	a.audit(r, "cms.install", app.ID+" → "+domain)
	a.jobResp(w, j.ID)
}

// ---------- PKI ----------

func (a *App) handlePKI(w http.ResponseWriter, r *http.Request) {
	var certs []store.CertMeta
	a.Store.View(func(d *store.Data) { certs = append(certs, d.Certs...) })
	if certs == nil {
		certs = []store.CertMeta{}
	}
	writeJSON(w, 200, map[string]any{"ca": a.PKI.Info(), "certs": certs})
}

func (a *App) handlePKICreateCA(w http.ResponseWriter, r *http.Request) {
	var in struct {
		CN, Org string
		Years   int
	}
	if !decode(w, r, &in) {
		return
	}
	if err := a.PKI.CreateCA(in.CN, in.Org, in.Years); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.audit(r, "pki.ca.create", in.CN)
	writeJSON(w, 201, a.PKI.Info())
}

func (a *App) handlePKICACert(w http.ResponseWriter, r *http.Request) {
	b, err := a.PKI.CACertPEM()
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="ca.crt"`)
	w.Write(b)
}

func (a *App) handlePKICRL(w http.ResponseWriter, r *http.Request) {
	var certs []store.CertMeta
	a.Store.View(func(d *store.Data) { certs = append(certs, d.Certs...) })
	b, err := a.PKI.CRL(certs)
	if err != nil {
		fail(w, 404, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="ca.crl.pem"`)
	w.Write(b)
}

func (a *App) handlePKIIssue(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Domain string
		SANs   []string
		Days   int
	}
	if !decode(w, r, &in) {
		return
	}
	meta, err := a.PKI.Issue(in.Domain, in.SANs, in.Days)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	_ = a.Store.Update(func(d *store.Data) error { d.Certs = append(d.Certs, meta); return nil })
	a.audit(r, "pki.issue", meta.Domain+" #"+meta.Serial)
	writeJSON(w, 201, meta)
}

func (a *App) handlePKICertDownload(w http.ResponseWriter, r *http.Request) {
	cert, _, ok := a.PKI.Paths(r.PathValue("serial"))
	if !ok {
		fail(w, 404, "сертификат не найден")
		return
	}
	b, err := os.ReadFile(cert)
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="fullchain.pem"`)
	w.Write(b)
}

// detachCert снимает сертификат с сайтов и переприменяет их конфиги (уже без HTTPS).
func (a *App) detachCert(ctx context.Context, serial string) []string {
	var sites []store.Site
	a.Store.View(func(d *store.Data) {
		for _, s := range d.Sites {
			if s.CertID == serial {
				sites = append(sites, s)
			}
		}
	})
	var problems []string
	for _, s := range sites {
		s.CertID = ""
		if _, err := a.applySite(ctx, s); err != nil {
			problems = append(problems, s.Domain+": "+err.Error())
			continue
		}
		_ = a.Store.Update(func(d *store.Data) error {
			for i := range d.Sites {
				if d.Sites[i].ID == s.ID {
					d.Sites[i].CertID = ""
				}
			}
			return nil
		})
	}
	return problems
}

func (a *App) handlePKIRevoke(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if _, ok := a.certMeta(serial); !ok {
		fail(w, 404, "сертификат не найден")
		return
	}
	err := a.Store.Update(func(d *store.Data) error {
		for i := range d.Certs {
			if d.Certs[i].Serial == serial {
				d.Certs[i].Revoked, d.Certs[i].RevokedAt = true, time.Now()
			}
		}
		return nil
	})
	if err != nil {
		fail(w, 500, err.Error())
		return
	}
	problems := a.detachCert(r.Context(), serial)
	a.audit(r, "pki.revoke", "#"+serial)
	writeJSON(w, 200, map[string]any{"ok": true, "warnings": problems})
}

func (a *App) handlePKIDelete(w http.ResponseWriter, r *http.Request) {
	serial := r.PathValue("serial")
	if _, ok := a.certMeta(serial); !ok {
		fail(w, 404, "сертификат не найден")
		return
	}
	problems := a.detachCert(r.Context(), serial)
	if len(problems) > 0 {
		fail(w, 400, "не удалось снять сертификат с сайтов: "+strings.Join(problems, "; "))
		return
	}
	_ = a.PKI.RemoveFiles(serial)
	_ = a.Store.Update(func(d *store.Data) error {
		for i := range d.Certs {
			if d.Certs[i].Serial == serial {
				d.Certs = append(d.Certs[:i], d.Certs[i+1:]...)
				break
			}
		}
		return nil
	})
	a.audit(r, "pki.delete", "#"+serial)
	writeJSON(w, 200, map[string]any{"ok": true})
}
