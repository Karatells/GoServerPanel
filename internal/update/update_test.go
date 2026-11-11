package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"v0.2.0", "0.1.0", true}, {"0.1.0", "0.1.0", false}, {"0.1.0", "0.2.0", false},
		{"1.0.0", "0.9.9", true}, {"0.10.0", "0.9.0", true}, {"1.0.0", "1.0.0-rc1", true},
		{"1.0.0-rc1", "1.0.0", false}, {"1.0.0-rc2", "1.0.0-rc1", true},
		{"dev", "0.1.0", false}, {"1.0.0", "dev", false}, {"garbage", "1.0.0", false},
	}
	for _, c := range cases {
		if got := newer(c.a, c.b); got != c.want {
			t.Errorf("newer(%q,%q)=%v want %v", c.a, c.b, got, c.want)
		}
	}
}

// fakeScript — «бинарник», который выводит версию (запускается как обычная программа).
func fakeScript(version string) []byte {
	return []byte("#!/bin/sh\necho \"goserverpanel " + version + "\"\n")
}

type fixture struct {
	srv *httptest.Server
	u   *Updater
	exe string
}

func newFixture(t *testing.T, tag string, bin []byte, sum string, withSum bool) *fixture {
	t.Helper()
	name, err := assetName()
	if err != nil {
		t.Skip(err)
	}
	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/repos/o/r/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		assets := []map[string]any{{"name": name, "browser_download_url": srvURL + "/dl/bin", "size": len(bin)}}
		if withSum {
			assets = append(assets, map[string]any{"name": name + ".sha256", "browser_download_url": srvURL + "/dl/sum", "size": 90})
		}
		json.NewEncoder(w).Encode(map[string]any{"tag_name": tag, "body": "notes", "html_url": "http://x", "assets": assets})
	})
	mux.HandleFunc("/dl/bin", func(w http.ResponseWriter, r *http.Request) { w.Write(bin) })
	mux.HandleFunc("/dl/sum", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(sum + "  " + name + "\n")) })
	srv := httptest.NewServer(mux)
	srvURL = srv.URL
	t.Cleanup(srv.Close)

	exe := filepath.Join(t.TempDir(), "goserverpanel")
	if err := os.WriteFile(exe, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	u := New("o/r", true)
	u.APIBase, u.Insecure, u.Exe = srv.URL, true, exe
	return &fixture{srv: srv, u: u, exe: exe}
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func withCurrent(t *testing.T, v string) {
	old := Current
	Current = v
	t.Cleanup(func() { Current = old })
}

func TestCheck(t *testing.T) {
	withCurrent(t, "0.1.0")
	bin := fakeScript("0.2.0")
	f := newFixture(t, "v0.2.0", bin, sha(bin), true)
	i := f.u.Check(context.Background(), true)
	if i.Error != "" || !i.Available || i.Latest != "0.2.0" || !i.CanApply || i.Notes != "notes" {
		t.Fatalf("unexpected info: %+v", i)
	}
	Current = "0.2.0"
	if i := f.u.Check(context.Background(), true); i.Available {
		t.Errorf("same version must not be available: %+v", i)
	}
	// отключённая проверка не обращается к сети
	f.u.Enabled = false
	f.srv.Close()
	if i := f.u.Check(context.Background(), true); i.Error == "" || i.Enabled {
		t.Errorf("disabled check must report it: %+v", i)
	}
}

func TestCheckNoReleases(t *testing.T) {
	withCurrent(t, "0.1.0")
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	u := New("o/r", true)
	u.APIBase, u.Insecure = srv.URL, true
	if i := u.Check(context.Background(), true); !strings.Contains(i.Error, "релизов пока нет") {
		t.Errorf("got %+v", i)
	}
}

func TestApplyAndRollback(t *testing.T) {
	withCurrent(t, "0.1.0")
	bin := fakeScript("0.2.0")
	f := newFixture(t, "v0.2.0", bin, sha(bin), true)
	var out bytes.Buffer
	ver, err := f.u.Apply(context.Background(), &out, false)
	if err != nil || ver != "0.2.0" {
		t.Fatalf("apply: %v\n%s", err, out.String())
	}
	if b, _ := os.ReadFile(f.exe); !bytes.Equal(b, bin) {
		t.Error("executable was not replaced")
	}
	if st, _ := os.Stat(f.exe); st.Mode().Perm()&0o111 == 0 {
		t.Error("new executable must be executable")
	}
	if b, _ := os.ReadFile(f.exe + ".bak"); string(b) != "OLD" {
		t.Error("backup of the previous binary missing")
	}
	if !f.u.base().HasBackup {
		t.Error("HasBackup must be reported")
	}
	// откат (резервная копия должна запускаться — подменим её рабочим скриптом)
	_ = os.WriteFile(f.exe+".bak", fakeScript("0.1.0"), 0o755)
	if err := f.u.Rollback(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(f.exe); !strings.Contains(string(b), "0.1.0") {
		t.Error("rollback did not restore the previous binary")
	}
	if err := f.u.Rollback(); err == nil {
		t.Error("second rollback without backup must fail")
	}
	// не оставлять временных файлов рядом с бинарником
	ents, _ := os.ReadDir(filepath.Dir(f.exe))
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".goserverpanel-new-") || strings.HasPrefix(e.Name(), ".gsp-write-test-") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
}

func TestApplyRefusals(t *testing.T) {
	withCurrent(t, "0.1.0")
	good := fakeScript("0.2.0")
	cases := []struct {
		name    string
		bin     []byte
		sum     string
		withSum bool
		want    string
	}{
		{"bad checksum", good, strings.Repeat("0", 64), true, "контрольная сумма не совпала"},
		{"no checksum asset", good, "", false, "нет файла контрольной суммы"},
		{"garbage checksum", good, "zz", true, "повреждён"},
		{"wrong version inside", fakeScript("9.9.9"), "", true, "не совпадает с релизом"},
		{"not executable", []byte("not a program"), "", true, "не запускается"},
	}
	for _, c := range cases {
		sum := c.sum
		if c.name == "wrong version inside" || c.name == "not executable" {
			sum = sha(c.bin) // сумма верна, но содержимое негодное
		}
		f := newFixture(t, "v0.2.0", c.bin, sum, c.withSum)
		_, err := f.u.Apply(context.Background(), &bytes.Buffer{}, false)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
		if b, _ := os.ReadFile(f.exe); string(b) != "OLD" {
			t.Errorf("%s: executable must stay untouched", c.name)
		}
		if _, err := os.Stat(f.exe + ".bak"); err == nil {
			t.Errorf("%s: no backup should be created on failure", c.name)
		}
		ents, _ := os.ReadDir(filepath.Dir(f.exe))
		if len(ents) != 1 {
			t.Errorf("%s: temp files left behind: %d entries", c.name, len(ents))
		}
	}
}

func TestDryRunAndHostAllowlist(t *testing.T) {
	withCurrent(t, "0.1.0")
	bin := fakeScript("0.2.0")
	f := newFixture(t, "v0.2.0", bin, sha(bin), true)
	var out bytes.Buffer
	if _, err := f.u.Apply(context.Background(), &out, true); err != nil || !strings.Contains(out.String(), "dry-run") {
		t.Fatalf("dry-run: %v %s", err, out.String())
	}
	if b, _ := os.ReadFile(f.exe); string(b) != "OLD" {
		t.Error("dry-run must not touch the binary")
	}
	// без Insecure допускаются только https и хосты GitHub
	u := New("o/r", true)
	for _, bad := range []string{"http://github.com/x", "https://evil.example/x", "https://github.com.evil.io/x", "ftp://github.com/x"} {
		if err := u.allowed(bad); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
	for _, ok := range []string{"https://github.com/o/r/releases/download/v1/x", "https://objects.githubusercontent.com/x", "https://api.github.com/repos/o/r"} {
		if err := u.allowed(ok); err != nil {
			t.Errorf("%s must be allowed: %v", ok, err)
		}
	}
	if i := (&Updater{Repo: "../evil", Enabled: true, client: http.DefaultClient, Hosts: map[string]bool{}}).Check(context.Background(), true); i.Error == "" {
		t.Error("invalid repo must be rejected")
	}
}
