package nginx

import (
	"strings"
	"testing"

	"goserverpanel/internal/store"
)

func TestValidateRejectsInjection(t *testing.T) {
	bad := []store.Site{
		{Domain: "evil.com; return 200", Root: "/var/www/x/y"},
		{Domain: "ok.com", Root: "/etc/passwd"},
		{Domain: "ok.com", Root: "/var/www/../etc"},
		{Domain: "ok.com", Root: "/var/www/a b"},
		{Domain: "ok.com", Aliases: []string{"a.com}{"}, Root: "/var/www/a/b"},
		{Domain: "ok.com", Proxies: []store.ProxyRule{{Path: "/", Upstreams: []string{"http://127.0.0.1:3000;evil"}}}},
		{Domain: "ok.com", Proxies: []store.ProxyRule{{Path: "/a b", Upstreams: []string{"http://127.0.0.1:3000"}}}},
		{Domain: "ok.com", Root: "/var/www/a/b", Redirects: []store.Redirect{{From: "/x", To: "http://a/;rm", Code: 301}}},
		{Domain: "ok.com", Root: "/var/www/a/b", MaxBody: "1m;x"},
		{Domain: "ok.com"},
	}
	for i, s := range bad {
		s := s
		if err := Validate(&s, "/var/www"); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
	good := store.Site{Domain: "Example.COM", Aliases: []string{"www.example.com"}, Root: "/var/www/example.com/public_html", PHPVersion: "8.3"}
	if err := Validate(&good, "/var/www"); err != nil || good.Domain != "example.com" {
		t.Fatalf("good site rejected: %v", err)
	}
}

func TestRender(t *testing.T) {
	s := store.Site{ID: "1", Domain: "example.com", Aliases: []string{"www.example.com"}, Root: "/var/www/example.com/public_html",
		PHPVersion: "8.3", ForceHTTPS: true, Cache: true, MaxBody: "64m",
		Proxies: []store.ProxyRule{
			{Path: "/api", Upstreams: []string{"http://127.0.0.1:3000"}, WebSocket: true},
			{Path: "/lb", Upstreams: []string{"http://10.0.0.1:80", "http://10.0.0.2:80"}, Balance: "least_conn"},
		}}
	out := Render(s, &TLS{Cert: "/c.pem", Key: "/k.pem"}, "/run/php/php8.3-fpm.sock", "/var/log/nginx", "")
	for _, want := range []string{
		"server_name example.com www.example.com;",
		"return 301 https://$host$request_uri;",
		"listen 443 ssl http2;", "ssl_certificate /c.pem;",
		"fastcgi_pass unix:/run/php/php8.3-fpm.sock;",
		"proxy_pass http://127.0.0.1:3000;", "proxy_set_header Upgrade $http_upgrade;",
		"upstream gsp_example_com_1 {", "least_conn;", "server 10.0.0.2:80;", "proxy_pass http://gsp_example_com_1;",
		"try_files $uri $uri/ /index.php?$args;", "expires 30d;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config lacks %q\n%s", want, out)
		}
	}
	if strings.Count(out, "listen 80;") != 1 {
		t.Errorf("expected exactly one http server")
	}
}

func TestRenderProtected(t *testing.T) {
	s := store.Site{ID: "1", Domain: "p.example.com", Root: "/var/www/p/public_html", MaxBody: "1m", Protected: true}
	out := Render(s, nil, "", "/var/log/nginx", "127.0.0.1:8443")
	for _, want := range []string{
		"auth_request /_gsp/verify;", "error_page 401 = @gsp_login;",
		"location = /_gsp/verify {", "internal;", "proxy_pass https://127.0.0.1:8443/gate/verify;",
		"location ^~ /_gsp/ {", "proxy_pass https://127.0.0.1:8443/gate/;", "proxy_set_header X-Gate-Host $host;",
		"return 302 /_gsp/login?next=$request_uri;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("protected config lacks %q\n%s", want, out)
		}
	}
	// без адреса панели защита не должна молча пропадать — сайт закрывается
	if out := Render(s, nil, "", "/var/log/nginx", ""); !strings.Contains(out, "return 503;") || strings.Contains(out, "auth_request") {
		t.Errorf("must fail closed without gate address:\n%s", out)
	}
	// незащищённый сайт не получает лишних директив
	s.Protected = false
	if out := Render(s, nil, "", "/var/log/nginx", "127.0.0.1:8443"); strings.Contains(out, "auth_request") || strings.Contains(out, "_gsp") {
		t.Error("unprotected site must not contain gate directives")
	}
	// ручной конфиг несовместим с защитой
	s.Protected, s.RawConfig = true, "server {}"
	if err := Validate(&s, "/var/www"); err == nil {
		t.Error("raw config + protected must be rejected")
	}
	for in, want := range map[string]string{"0.0.0.0:8443": "127.0.0.1:8443", ":9000": "127.0.0.1:9000", "[::]:8443": "127.0.0.1:8443", "10.1.2.3:8443": "10.1.2.3:8443", "bad": ""} {
		if got := GateAddr(in); got != want {
			t.Errorf("GateAddr(%q)=%q want %q", in, got, want)
		}
	}
}
