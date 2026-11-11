// Package nginx: генерация конфигов виртуальных хостов, проверка `nginx -t`, откат при ошибке.
package nginx

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"goserverpanel/internal/config"
	"goserverpanel/internal/execx"
	"goserverpanel/internal/store"
)

var (
	DomainRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	pathRe     = regexp.MustCompile(`^/[A-Za-z0-9._~\-/]*$`)
	redirToRe  = regexp.MustCompile(`^(https?://|/)[^\s"';{}$\\]*$`)
	maxBodyRe  = regexp.MustCompile(`^\d{1,5}[kKmMgG]?$`)
	phpVerRe   = regexp.MustCompile(`^\d\.\d$`)
	hostPortRe = regexp.MustCompile(`^[A-Za-z0-9._\-]+(:\d{1,5})?$|^\[[0-9A-Fa-f:]+\](:\d{1,5})?$`)
)

type TLS struct{ Cert, Key string }

type Manager struct {
	Cfg *config.Config
	Run *execx.Runner
}

// Validate проверяет и нормализует пользовательский ввод (всё, что попадает в конфиг).
func Validate(s *store.Site, wwwRoot string) error {
	s.Domain = strings.ToLower(strings.TrimSpace(s.Domain))
	if len(s.Domain) > 253 || !DomainRe.MatchString(s.Domain) {
		return fmt.Errorf("некорректный домен %q", s.Domain)
	}
	seen := map[string]bool{s.Domain: true}
	aliases := []string{}
	for _, a := range s.Aliases {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" || seen[a] {
			continue
		}
		if len(a) > 253 || !DomainRe.MatchString(a) {
			return fmt.Errorf("некорректный алиас %q", a)
		}
		seen[a] = true
		aliases = append(aliases, a)
	}
	s.Aliases = aliases
	if s.Root != "" {
		s.Root = filepath.Clean(s.Root)
		root := filepath.Clean(wwwRoot)
		if !strings.HasPrefix(s.Root, root+string(filepath.Separator)) {
			return fmt.Errorf("корневая директория должна находиться внутри %s", root)
		}
		if strings.ContainsAny(s.Root, " \t\n\"';{}$\\") {
			return fmt.Errorf("недопустимые символы в пути корня")
		}
	}
	if s.PHPVersion != "" && !phpVerRe.MatchString(s.PHPVersion) {
		return fmt.Errorf("некорректная версия PHP %q", s.PHPVersion)
	}
	if s.PHPVersion != "" && s.Root == "" {
		return fmt.Errorf("для PHP нужна корневая директория")
	}
	if s.MaxBody == "" {
		s.MaxBody = "64m"
	}
	if !maxBodyRe.MatchString(s.MaxBody) {
		return fmt.Errorf("некорректный client_max_body_size")
	}
	for i := range s.Proxies {
		p := &s.Proxies[i]
		if p.Path == "" {
			p.Path = "/"
		}
		if !pathRe.MatchString(p.Path) {
			return fmt.Errorf("некорректный путь прокси %q", p.Path)
		}
		if len(p.Upstreams) == 0 {
			return fmt.Errorf("для прокси %q не указан upstream", p.Path)
		}
		if len(p.Upstreams) > 16 {
			return fmt.Errorf("слишком много upstream-серверов")
		}
		var scheme string
		for _, raw := range p.Upstreams {
			u, err := url.Parse(raw)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || !hostPortRe.MatchString(u.Host) || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return fmt.Errorf("некорректный upstream %q (ожидается http(s)://host:port)", raw)
			}
			if len(p.Upstreams) > 1 && (u.Path != "" && u.Path != "/") {
				return fmt.Errorf("при балансировке upstream не может содержать путь")
			}
			if scheme != "" && scheme != u.Scheme {
				return fmt.Errorf("все upstream одной группы должны использовать одну схему")
			}
			scheme = u.Scheme
			if strings.ContainsAny(u.Path, " \t\"';{}$\\") {
				return fmt.Errorf("недопустимые символы в upstream")
			}
		}
		switch p.Balance {
		case "", "round_robin", "least_conn", "ip_hash":
		default:
			return fmt.Errorf("неизвестный алгоритм балансировки %q", p.Balance)
		}
	}
	for _, r := range s.Redirects {
		if !pathRe.MatchString(r.From) || !redirToRe.MatchString(r.To) {
			return fmt.Errorf("некорректный редирект %q → %q", r.From, r.To)
		}
		if r.Code != 301 && r.Code != 302 && r.Code != 307 && r.Code != 308 {
			return fmt.Errorf("код редиректа должен быть 301/302/307/308")
		}
	}
	if s.Root == "" && len(s.Proxies) == 0 && s.RawConfig == "" {
		return fmt.Errorf("укажите корневую директорию или правило прокси")
	}
	return nil
}

func upstreamName(domain string, i int) string {
	return fmt.Sprintf("gsp_%s_%d", strings.NewReplacer(".", "_", "-", "_").Replace(domain), i)
}

// Render генерирует конфигурацию сайта.
func Render(s store.Site, tls *TLS, phpSock, logDir string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Managed by GoServerPanel (site %s). Ручные правки будут перезаписаны.\n", s.ID)

	for i, p := range s.Proxies {
		if len(p.Upstreams) < 2 {
			continue
		}
		fmt.Fprintf(&b, "upstream %s {\n", upstreamName(s.Domain, i))
		if p.Balance == "least_conn" || p.Balance == "ip_hash" {
			fmt.Fprintf(&b, "    %s;\n", strings.ReplaceAll(p.Balance, "_", "_"))
		}
		for _, raw := range p.Upstreams {
			u, _ := url.Parse(raw)
			fmt.Fprintf(&b, "    server %s;\n", u.Host)
		}
		b.WriteString("}\n\n")
	}

	names := strings.Join(append([]string{s.Domain}, s.Aliases...), " ")
	body := func() string {
		var l strings.Builder
		fmt.Fprintf(&l, "    server_name %s;\n", names)
		fmt.Fprintf(&l, "    client_max_body_size %s;\n", s.MaxBody)
		fmt.Fprintf(&l, "    access_log %s/%s.access.log;\n", logDir, s.Domain)
		fmt.Fprintf(&l, "    error_log %s/%s.error.log;\n", logDir, s.Domain)
		if s.Root != "" {
			fmt.Fprintf(&l, "    root %s;\n    index index.php index.html index.htm;\n", s.Root)
		}
		for _, r := range s.Redirects {
			fmt.Fprintf(&l, "\n    location %s {\n        return %d %s;\n    }\n", r.From, r.Code, r.To)
		}
		rootProxied := false
		for i, p := range s.Proxies {
			if p.Path == "/" {
				rootProxied = true
			}
			target := p.Upstreams[0]
			if len(p.Upstreams) > 1 {
				u, _ := url.Parse(p.Upstreams[0])
				target = u.Scheme + "://" + upstreamName(s.Domain, i)
			}
			fmt.Fprintf(&l, "\n    location %s {\n        proxy_pass %s;\n        proxy_http_version 1.1;\n", p.Path, target)
			l.WriteString("        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n")
			l.WriteString("        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n")
			if p.WebSocket {
				l.WriteString("        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection \"upgrade\";\n        proxy_read_timeout 3600s;\n")
			} else {
				l.WriteString("        proxy_set_header Connection \"\";\n")
			}
			l.WriteString("    }\n")
		}
		if s.Root != "" {
			l.WriteString("\n    location ~ /\\.(?!well-known) {\n        deny all;\n    }\n")
			if s.Cache {
				l.WriteString("\n    location ~* \\.(?:css|js|jpe?g|gif|png|svg|ico|webp|woff2?|ttf|eot)$ {\n        expires 30d;\n        access_log off;\n        add_header Cache-Control \"public\";\n    }\n")
			}
			if !rootProxied {
				if s.PHPVersion != "" {
					l.WriteString("\n    location / {\n        try_files $uri $uri/ /index.php?$args;\n    }\n")
				} else {
					l.WriteString("\n    location / {\n        try_files $uri $uri/ =404;\n    }\n")
				}
			}
			if s.PHPVersion != "" {
				fmt.Fprintf(&l, "\n    location ~ \\.php$ {\n        try_files $uri =404;\n        include fastcgi_params;\n        fastcgi_split_path_info ^(.+\\.php)(/.+)$;\n        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n        fastcgi_param PATH_INFO $fastcgi_path_info;\n        fastcgi_pass unix:%s;\n    }\n", phpSock)
			}
		}
		return l.String()
	}

	if tls != nil && s.ForceHTTPS {
		fmt.Fprintf(&b, "server {\n    listen 80;\n    server_name %s;\n    return 301 https://$host$request_uri;\n}\n\n", names)
	} else {
		fmt.Fprintf(&b, "server {\n    listen 80;\n%s}\n\n", body())
	}
	if tls != nil {
		fmt.Fprintf(&b, "server {\n    listen 443 ssl http2;\n    ssl_certificate %s;\n    ssl_certificate_key %s;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_prefer_server_ciphers off;\n%s}\n", tls.Cert, tls.Key, body())
	}
	return b.String()
}

func (m *Manager) Installed() bool { return execx.Exists(m.Cfg.NginxBin) }

// Install устанавливает nginx через apt и включает его.
func (m *Manager) Install(ctx context.Context, w io.Writer) error {
	o := execx.Opts{Stdout: w}
	fmt.Fprintln(w, "→ apt-get update")
	if _, err := m.Run.Do(ctx, o, "apt-get", "update"); err != nil {
		return err
	}
	fmt.Fprintln(w, "→ apt-get install nginx")
	if _, err := m.Run.Do(ctx, o, "apt-get", "install", "-y", "nginx"); err != nil {
		return err
	}
	fmt.Fprintln(w, "→ systemctl enable --now nginx")
	_, err := m.Run.Do(ctx, o, "systemctl", "enable", "--now", "nginx")
	return err
}

func (m *Manager) confPath(domain string) string {
	return filepath.Join(m.Cfg.NginxAvailable, "gsp-"+domain+".conf")
}
func (m *Manager) linkPath(domain string) string {
	return filepath.Join(m.Cfg.NginxEnabled, "gsp-"+domain+".conf")
}

func (m *Manager) setLink(domain string, enabled bool) error {
	lp := m.linkPath(domain)
	_ = os.Remove(lp)
	if !enabled {
		return nil
	}
	if err := os.MkdirAll(m.Cfg.NginxEnabled, 0o755); err != nil {
		return err
	}
	return os.Symlink(m.confPath(domain), lp)
}

// Apply записывает конфиг, проверяет `nginx -t` и перезагружает nginx.
// При ошибке проверки прежнее состояние восстанавливается, а изменения не применяются.
func (m *Manager) Apply(ctx context.Context, s store.Site, tls *TLS, phpSock string) (rendered string, err error) {
	rendered = s.RawConfig
	if rendered == "" {
		rendered = Render(s, tls, phpSock, m.Cfg.NginxLogDir)
	}
	cp := m.confPath(s.Domain)
	old, oldErr := os.ReadFile(cp)
	_, linkErr := os.Lstat(m.linkPath(s.Domain))
	hadLink := linkErr == nil

	if err := os.MkdirAll(m.Cfg.NginxAvailable, 0o755); err != nil {
		return rendered, err
	}
	if err := os.WriteFile(cp, []byte(rendered), 0o644); err != nil {
		return rendered, err
	}
	if err := m.setLink(s.Domain, s.Enabled); err != nil {
		return rendered, err
	}
	if out, terr := m.Test(ctx); terr != nil {
		if oldErr == nil {
			_ = os.WriteFile(cp, old, 0o644)
		} else {
			_ = os.Remove(cp)
		}
		_ = m.setLink(s.Domain, hadLink && oldErr == nil)
		return rendered, fmt.Errorf("nginx -t: %s", out)
	}
	if rerr := m.Reload(ctx); rerr != nil {
		return rendered, fmt.Errorf("конфиг применён, но перезагрузка nginx не удалась: %w", rerr)
	}
	return rendered, nil
}

func (m *Manager) Remove(ctx context.Context, domain string) error {
	_ = os.Remove(m.linkPath(domain))
	_ = os.Remove(m.confPath(domain))
	if _, err := m.Test(ctx); err != nil {
		return err
	}
	return m.Reload(ctx)
}

func (m *Manager) Test(ctx context.Context) (string, error) {
	return m.Run.Do(ctx, execx.Opts{}, m.Cfg.NginxBin, "-t")
}

func (m *Manager) Reload(ctx context.Context) error {
	if _, err := m.Run.Do(ctx, execx.Opts{}, "systemctl", "reload", "nginx"); err == nil {
		return nil
	}
	_, err := m.Run.Do(ctx, execx.Opts{}, m.Cfg.NginxBin, "-s", "reload")
	return err
}

// TailLog возвращает последние n строк access/error лога сайта.
func (m *Manager) TailLog(domain, kind string, n int) (string, error) {
	if !DomainRe.MatchString(domain) || (kind != "access" && kind != "error") {
		return "", fmt.Errorf("некорректные параметры")
	}
	if n <= 0 || n > 2000 {
		n = 200
	}
	f, err := os.Open(filepath.Join(m.Cfg.NginxLogDir, domain+"."+kind+".log"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	const window = 512 * 1024
	off := st.Size() - window
	if off < 0 {
		off = 0
	}
	buf := make([]byte, st.Size()-off)
	if _, err := f.ReadAt(buf, off); err != nil && err.Error() != "EOF" {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(buf), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n"), nil
}
