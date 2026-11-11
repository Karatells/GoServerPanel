package installer

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractZipSlipAndStrip(t *testing.T) {
	dir := t.TempDir()
	zp := filepath.Join(dir, "a.zip")
	f, _ := os.Create(zp)
	zw := zip.NewWriter(f)
	for name, body := range map[string]string{
		"upload/index.php":       "ok",
		"upload/sub/x.txt":       "ok",
		"other/skip.txt":         "no",
		"upload/../../escape.sh": "bad",
		"/abs/evil":              "bad",
	} {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	zw.Close()
	f.Close()

	dst := filepath.Join(dir, "site")
	if err := extractZip(zp, dst, "upload/"); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"index.php", "sub/x.txt"} {
		if _, err := os.Stat(filepath.Join(dst, p)); err != nil {
			t.Errorf("missing %s", p)
		}
	}
	for _, p := range []string{filepath.Join(dir, "escape.sh"), filepath.Join(dst, "skip.txt"), "/abs/evil"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s must not exist", p)
		}
	}
}

func TestWPConfigQuoting(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "wp-config-sample.php"), []byte("<?php"), 0o644)
	if err := writeWPConfig(Params{Dir: dir, DBName: "db", DBUser: "u", DBPass: `p'a\ss`, DBHost: "localhost"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "wp-config.php"))
	if want := `define( 'DB_PASSWORD', 'p\'a\\ss' );`; !contains(string(b), want) {
		t.Errorf("password not escaped properly:\n%s", b)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
