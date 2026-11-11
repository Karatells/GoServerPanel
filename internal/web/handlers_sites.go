package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"goserverpanel/internal/execx"
	"goserverpanel/internal/nginx"
	"goserverpanel/internal/store"
)

func (a *App) findSite(id string) (s store.Site, ok bool) {
	a.Store.View(func(d *store.Data) {
		for _, x := range d.Sites {
			if x.ID == id {
				s, ok = x, true
			}
		}
	})
	return
}

func (a *App) certMeta(serial string) (c store.CertMeta, ok bool) {
	a.Store.View(func(d *store.Data) {
		for _, x := range d.Certs {
			if x.Serial == serial {
				c, ok = x, true
			}
		}
	})
	return
}

func (a *App) siteTLS(s store.Site) *nginx.TLS {
	if s.CertID == "" {
		return nil
	}
	if m, ok := a.certMeta(s.CertID); !ok || m.Revoked {
		return nil
	}
	if cert, key, ok := a.PKI.Paths(s.CertID); ok {
		return &nginx.TLS{Cert: cert, Key: key}
	}
	return nil
}

func (a *App) applySite(ctx context.Context, s store.Site) (string, error) {
	sock := ""
	if s.PHPVersion != "" {
		sock = a.PHP.Socket(s.PHPVersion)
	}
	return a.Nginx.Apply(ctx, s, a.siteTLS(s), sock)
}

// ensureTraversable добавляет r-x для group/other на каждом каталоге от root вверх до www_root,
// иначе nginx/php-fpm (www-data) не смогут дойти до файлов сайта (stat() ... Permission denied).
func (a *App) ensureTraversable(root string) {
	base := filepath.Clean(a.Cfg.WWWRoot)
	for d := filepath.Clean(root); d == base || strings.HasPrefix(d, base+string(filepath.Separator)); d = filepath.Dir(d) {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			if m := st.Mode().Perm(); m&0o055 != 0o055 {
				_ = os.Chmod(d, m|0o055)
			}
		}
		if d == base {
			break
		}
	}
}

// FixSitePerms исправляет права каталогов всех сайтов (вызывается при старте панели).
func (a *App) FixSitePerms() {
	a.Store.View(func(d *store.Data) {
		for _, s := range d.Sites {
			if s.Root != "" {
				a.ensureTraversable(s.Root)
			}
		}
	})
}

func (a *App) prepareRoot(root, phpVer string) error {
	if root == "" {
		return nil
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return err
	}
	a.ensureTraversable(root)
	if ents, _ := os.ReadDir(root); len(ents) == 0 {
		page := "<!doctype html><meta charset=utf-8><title>Сайт готов</title><h1>Сайт создан в GoServerPanel</h1>\n"
		_ = os.WriteFile(filepath.Join(root, "index.html"), []byte(page), 0o644)
	}
	if !a.Cfg.DryRun && a.Cfg.WebUser != "" {
		_, _ = a.Run.Do(context.Background(), execx.Opts{}, "chown", "-R", a.Cfg.WebUser+":"+a.Cfg.WebUser, root)
	}
	return nil
}

func (a *App) checkSiteRefs(s *store.Site, selfID string) error {
	if s.PHPVersion != "" && !a.Cfg.DryRun && !a.PHP.Installed(s.PHPVersion) {
		return fmt.Errorf("PHP %s не установлен — установите его в разделе «PHP & Модули»", s.PHPVersion)
	}
	if s.CertID != "" {
		if m, ok := a.certMeta(s.CertID); !ok || m.Revoked {
			return fmt.Errorf("сертификат не найден или отозван")
		}
	}
	var clash string
	a.Store.View(func(d *store.Data) {
		names := map[string]bool{s.Domain: true}
		for _, x := range s.Aliases {
			names[x] = true
		}
		for _, o := range d.Sites {
			if o.ID == selfID {
				continue
			}
			for _, n := range append([]string{o.Domain}, o.Aliases...) {
				if names[n] {
					clash = n
				}
			}
		}
	})
	if clash != "" {
		return fmt.Errorf("имя %q уже используется другим сайтом", clash)
	}
	return nil
}

// createSite — общая логика создания сайта (используется API и установщиком CMS).
func (a *App) createSite(ctx context.Context, s *store.Site) error {
	if s.Root == "" && len(s.Proxies) == 0 && s.RawConfig == "" {
		s.Root = filepath.Join(a.Cfg.WWWRoot, strings.ToLower(strings.TrimSpace(s.Domain)), "public_html")
	}
	if err := nginx.Validate(s, a.Cfg.WWWRoot); err != nil {
		return err
	}
	if err := a.checkSiteRefs(s, ""); err != nil {
		return err
	}
	s.ID, s.Created, s.Enabled = store.NewID(), time.Now(), true
	if err := a.prepareRoot(s.Root, s.PHPVersion); err != nil {
		return err
	}
	if _, err := a.applySite(ctx, *s); err != nil {
		return err
	}
	return a.Store.Update(func(d *store.Data) error { d.Sites = append(d.Sites, *s); return nil })
}

func (a *App) handleSites(w http.ResponseWriter, r *http.Request) {
	var list []store.Site
	a.Store.View(func(d *store.Data) { list = append(list, d.Sites...) })
	if list == nil {
		list = []store.Site{}
	}
	writeJSON(w, 200, list)
}

func (a *App) handleSiteGet(w http.ResponseWriter, r *http.Request) {
	s, ok := a.findSite(r.PathValue("id"))
	if !ok {
		fail(w, 404, "сайт не найден")
		return
	}
	writeJSON(w, 200, s)
}

func (a *App) handleSiteCreate(w http.ResponseWriter, r *http.Request) {
	var s store.Site
	if !decode(w, r, &s) {
		return
	}
	if err := a.createSite(r.Context(), &s); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.audit(r, "site.create", s.Domain)
	writeJSON(w, 201, s)
}

func (a *App) handleSiteUpdate(w http.ResponseWriter, r *http.Request) {
	old, ok := a.findSite(r.PathValue("id"))
	if !ok {
		fail(w, 404, "сайт не найден")
		return
	}
	var s store.Site
	if !decode(w, r, &s) {
		return
	}
	s.ID, s.Created, s.CMS = old.ID, old.Created, old.CMS
	if err := nginx.Validate(&s, a.Cfg.WWWRoot); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err := a.checkSiteRefs(&s, s.ID); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err := a.prepareRoot(s.Root, s.PHPVersion); err != nil {
		fail(w, 500, err.Error())
		return
	}
	if _, err := a.applySite(r.Context(), s); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if old.Domain != s.Domain {
		_ = a.Nginx.Remove(r.Context(), old.Domain)
	}
	_ = a.Store.Update(func(d *store.Data) error {
		for i := range d.Sites {
			if d.Sites[i].ID == s.ID {
				d.Sites[i] = s
			}
		}
		return nil
	})
	a.audit(r, "site.update", s.Domain)
	writeJSON(w, 200, s)
}

func (a *App) handleSiteDelete(w http.ResponseWriter, r *http.Request) {
	s, ok := a.findSite(r.PathValue("id"))
	if !ok {
		fail(w, 404, "сайт не найден")
		return
	}
	if err := a.Nginx.Remove(r.Context(), s.Domain); err != nil {
		fail(w, 500, err.Error())
		return
	}
	_ = a.Store.Update(func(d *store.Data) error {
		for i := range d.Sites {
			if d.Sites[i].ID == s.ID {
				d.Sites = append(d.Sites[:i], d.Sites[i+1:]...)
				break
			}
		}
		return nil
	})
	if r.URL.Query().Get("purge") == "1" && s.Root != "" {
		// удаляем каталог сайта только внутри www_root
		base := filepath.Join(a.Cfg.WWWRoot, s.Domain)
		target := s.Root
		if strings.HasPrefix(s.Root, base+string(filepath.Separator)) {
			target = base
		}
		if strings.HasPrefix(target, filepath.Clean(a.Cfg.WWWRoot)+string(filepath.Separator)) {
			_ = os.RemoveAll(target)
		}
	}
	a.audit(r, "site.delete", s.Domain)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleSiteConfigGet(w http.ResponseWriter, r *http.Request) {
	s, ok := a.findSite(r.PathValue("id"))
	if !ok {
		fail(w, 404, "сайт не найден")
		return
	}
	sock := ""
	if s.PHPVersion != "" {
		sock = a.PHP.Socket(s.PHPVersion)
	}
	gen := nginx.Render(s, a.siteTLS(s), sock, a.Cfg.NginxLogDir, nginx.GateAddr(a.Cfg.Listen))
	cfg := gen
	if s.RawConfig != "" {
		cfg = s.RawConfig
	}
	writeJSON(w, 200, map[string]any{"config": cfg, "generated": gen, "raw": s.RawConfig != ""})
}

// handleSiteConfigPut сохраняет ручной конфиг (пустой — вернуться к генерируемому). Применяется только после nginx -t.
func (a *App) handleSiteConfigPut(w http.ResponseWriter, r *http.Request) {
	s, ok := a.findSite(r.PathValue("id"))
	if !ok {
		fail(w, 404, "сайт не найден")
		return
	}
	var in struct{ Config string }
	if !decode(w, r, &in) {
		return
	}
	s.RawConfig = strings.ReplaceAll(in.Config, "\r\n", "\n")
	if s.RawConfig != "" && s.Protected {
		fail(w, 400, "сайт защищён входом: ручной конфиг не поддерживает защиту — сначала отключите её")
		return
	}
	if s.RawConfig == "" && s.Root == "" && len(s.Proxies) == 0 {
		fail(w, 400, "у сайта нет ни корня, ни прокси — генерируемый конфиг был бы пустым")
		return
	}
	if _, err := a.applySite(r.Context(), s); err != nil {
		fail(w, 400, err.Error())
		return
	}
	_ = a.Store.Update(func(d *store.Data) error {
		for i := range d.Sites {
			if d.Sites[i].ID == s.ID {
				d.Sites[i].RawConfig = s.RawConfig
			}
		}
		return nil
	})
	a.audit(r, "site.config", s.Domain)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleSiteLogs(w http.ResponseWriter, r *http.Request) {
	s, ok := a.findSite(r.PathValue("id"))
	if !ok {
		fail(w, 404, "сайт не найден")
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	out, err := a.Nginx.TailLog(s.Domain, r.URL.Query().Get("kind"), n)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"log": out})
}

func (a *App) handleNginxStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"installed": a.Nginx.Installed()})
}

func (a *App) handleNginxInstall(w http.ResponseWriter, r *http.Request) {
	if a.Nginx.Installed() {
		fail(w, 400, "nginx уже установлен")
		return
	}
	j := a.Jobs.Start("Установка nginx", func(ctx context.Context, w io.Writer) error { return a.Nginx.Install(ctx, w) })
	a.audit(r, "nginx.install", "")
	a.jobResp(w, j.ID)
}

func (a *App) handleNginxTest(w http.ResponseWriter, r *http.Request) {
	out, err := a.Nginx.Test(r.Context())
	writeJSON(w, 200, map[string]any{"ok": err == nil, "output": out})
}

func (a *App) handleNginxReload(w http.ResponseWriter, r *http.Request) {
	if out, err := a.Nginx.Test(r.Context()); err != nil {
		fail(w, 400, "nginx -t: "+out)
		return
	}
	if err := a.Nginx.Reload(r.Context()); err != nil {
		fail(w, 500, err.Error())
		return
	}
	a.audit(r, "nginx.reload", "")
	writeJSON(w, 200, map[string]any{"ok": true})
}
