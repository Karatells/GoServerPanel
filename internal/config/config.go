// Package config загружает config.yaml (плоское подмножество YAML: скаляры и списки).
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	Listen          string
	DataDir         string
	TLSCert         string
	TLSKey          string
	AllowCIDRs      []string
	DryRun          bool
	NginxAvailable  string
	NginxEnabled    string
	NginxBin        string
	NginxLogDir     string
	WWWRoot         string
	WebUser         string
	PHPEtcDir       string
	PHPSocketDir    string
	FilesRoots      []string
	Shell           string
	SessionHours    int
	TerminalEnabled bool
}

func Default() Config {
	return Config{
		Listen:          "0.0.0.0:8443",
		DataDir:         "/var/lib/goserverpanel",
		NginxAvailable:  "/etc/nginx/sites-available",
		NginxEnabled:    "/etc/nginx/sites-enabled",
		NginxBin:        "nginx",
		NginxLogDir:     "/var/log/nginx",
		WWWRoot:         "/var/www",
		WebUser:         "www-data",
		PHPEtcDir:       "/etc/php",
		PHPSocketDir:    "/run/php",
		FilesRoots:      []string{"/var/www", "/etc/nginx"},
		Shell:           "/bin/bash",
		SessionHours:    12,
		TerminalEnabled: true,
	}
}

// Load читает файл; отсутствующий файл — не ошибка (используются значения по умолчанию).
func Load(path string) (Config, error) {
	c := Default()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, c.finish()
		}
		return c, err
	}
	defer f.Close()

	kv := map[string][]string{}
	var listKey string
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue
		}
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "- ") && listKey != "" {
			kv[listKey] = append(kv[listKey], unquote(strings.TrimSpace(t[2:])))
			continue
		}
		k, v, ok := strings.Cut(t, ":")
		if !ok {
			return c, fmt.Errorf("%s:%d: ожидалось key: value", path, n)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if v == "" {
			listKey = k
			kv[k] = []string{}
			continue
		}
		listKey = ""
		if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
			items := []string{}
			for _, p := range strings.Split(v[1:len(v)-1], ",") {
				if p = strings.TrimSpace(p); p != "" {
					items = append(items, unquote(p))
				}
			}
			kv[k] = items
			continue
		}
		kv[k] = []string{unquote(v)}
	}
	if err := sc.Err(); err != nil {
		return c, err
	}

	str := func(key string, dst *string) {
		if v, ok := kv[key]; ok && len(v) == 1 {
			*dst = v[0]
		}
	}
	boolean := func(key string, dst *bool) {
		if v, ok := kv[key]; ok && len(v) == 1 {
			*dst, _ = strconv.ParseBool(v[0])
		}
	}
	str("listen", &c.Listen)
	str("data_dir", &c.DataDir)
	str("tls_cert", &c.TLSCert)
	str("tls_key", &c.TLSKey)
	str("nginx_sites_available", &c.NginxAvailable)
	str("nginx_sites_enabled", &c.NginxEnabled)
	str("nginx_bin", &c.NginxBin)
	str("nginx_log_dir", &c.NginxLogDir)
	str("www_root", &c.WWWRoot)
	str("web_user", &c.WebUser)
	str("php_etc_dir", &c.PHPEtcDir)
	str("php_socket_dir", &c.PHPSocketDir)
	str("shell", &c.Shell)
	boolean("dry_run", &c.DryRun)
	boolean("terminal_enabled", &c.TerminalEnabled)
	if v, ok := kv["session_hours"]; ok && len(v) == 1 {
		if h, err := strconv.Atoi(v[0]); err == nil && h > 0 {
			c.SessionHours = h
		}
	}
	if v, ok := kv["allow_cidrs"]; ok {
		c.AllowCIDRs = v
	}
	if v, ok := kv["files_roots"]; ok {
		c.FilesRoots = v
	}
	return c, c.finish()
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

func (c *Config) finish() error {
	var err error
	if c.DataDir, err = filepath.Abs(c.DataDir); err != nil {
		return err
	}
	if c.TLSCert == "" {
		c.TLSCert = filepath.Join(c.DataDir, "panel.crt")
	}
	if c.TLSKey == "" {
		c.TLSKey = filepath.Join(c.DataDir, "panel.key")
	}
	return nil
}
