// Package update — самообновление панели из GitHub Releases.
//
// Порядок: запрос последнего релиза → загрузка бинарника и .sha256 → проверка суммы →
// пробный запуск `-version` (версия должна совпасть с релизом) → атомарная замена с резервной
// копией (.bak) → перезапуск процесса через exec (PID сохраняется, systemd ничего не замечает).
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Current — версия сборки. Переопределяется при сборке релиза:
// -ldflags "-X goserverpanel/internal/update.Current=1.2.3"
var Current = "0.2.0"

const (
	maxBinary   = 128 << 20
	cacheTTL    = 10 * time.Minute
	defaultRepo = "Karatells/GoServerPanel"
)

type Info struct {
	Current   string    `json:"current"`
	Latest    string    `json:"latest"`
	Available bool      `json:"available"`
	Notes     string    `json:"notes"`
	URL       string    `json:"url"`
	Published time.Time `json:"published,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
	Error     string    `json:"error,omitempty"`
	CanApply  bool      `json:"can_apply"`
	Reason    string    `json:"reason,omitempty"` // почему обновление недоступно
	HasBackup bool      `json:"has_backup"`
	Enabled   bool      `json:"enabled"`
}

type release struct {
	Tag        string    `json:"tag_name"`
	Body       string    `json:"body"`
	HTMLURL    string    `json:"html_url"`
	Published  time.Time `json:"published_at"`
	Draft      bool      `json:"draft"`
	Prerelease bool      `json:"prerelease"`
	Assets     []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

type Updater struct {
	Repo    string
	Enabled bool
	// настраиваются в тестах
	APIBase  string
	Insecure bool            // разрешить http и любые хосты (только для тестов)
	Hosts    map[string]bool // разрешённые хосты загрузки
	Exe      string          // путь к исполняемому файлу панели

	client *http.Client
	mu     sync.Mutex
	cached Info
	rel    *release
}

func New(repo string, enabled bool) *Updater {
	if repo == "" {
		repo = defaultRepo
	}
	exe, _ := os.Executable()
	if r, err := filepath.EvalSymlinks(exe); err == nil {
		exe = r
	}
	return &Updater{
		Repo: repo, Enabled: enabled, APIBase: "https://api.github.com", Exe: exe,
		client: &http.Client{Timeout: 15 * time.Second},
		Hosts: map[string]bool{
			"api.github.com": true, "github.com": true,
			"objects.githubusercontent.com":        true,
			"release-assets.githubusercontent.com": true,
		},
	}
}

var repoRe = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)

// ---------- версии ----------

var semRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$`)

type semver struct {
	n   [3]int
	pre string
}

func parseSemver(s string) (semver, bool) {
	m := semRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return semver{}, false
	}
	var v semver
	for i := 0; i < 3; i++ {
		v.n[i], _ = strconv.Atoi(m[i+1])
	}
	v.pre = m[4]
	return v, true
}

// newer сообщает, что a строго новее b.
func newer(a, b string) bool {
	x, ok1 := parseSemver(a)
	y, ok2 := parseSemver(b)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if x.n[i] != y.n[i] {
			return x.n[i] > y.n[i]
		}
	}
	if x.pre == y.pre {
		return false
	}
	if x.pre == "" { // релиз новее пререлиза
		return true
	}
	if y.pre == "" {
		return false
	}
	return x.pre > y.pre
}

// ---------- проверка ----------

func (u *Updater) allowed(raw string) error {
	if u.Insecure {
		return nil
	}
	p, err := url.Parse(raw)
	if err != nil || p.Scheme != "https" || !u.Hosts[strings.ToLower(p.Hostname())] {
		return fmt.Errorf("адрес загрузки %q не разрешён", raw)
	}
	return nil
}

func (u *Updater) get(ctx context.Context, raw string, limit int64, accept string) (*http.Response, error) {
	if err := u.allowed(raw); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "GoServerPanel/"+Current)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	c := *u.client
	if limit > 1<<20 {
		c.Timeout = 10 * time.Minute
	}
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 {
			return errors.New("слишком много перенаправлений")
		}
		return u.allowed(r.URL.String())
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		if resp.StatusCode == 404 {
			return nil, errors.New("релизов пока нет (HTTP 404)")
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return resp, nil
}

func assetName() (string, error) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return "", fmt.Errorf("платформа %s/%s не поддерживается", runtime.GOOS, runtime.GOARCH)
	}
	return "goserverpanel-linux-" + runtime.GOARCH, nil
}

func (u *Updater) bakPath() string { return u.Exe + ".bak" }

func (u *Updater) base() Info {
	i := Info{Current: Current, Enabled: u.Enabled}
	if _, err := os.Stat(u.bakPath()); err == nil {
		i.HasBackup = true
	}
	return i
}

// canWrite проверяет, что каталог с бинарником доступен для записи (нужно для атомарной замены).
func (u *Updater) canWrite() error {
	f, err := os.CreateTemp(filepath.Dir(u.Exe), ".gsp-write-test-*")
	if err != nil {
		return fmt.Errorf("нет прав на запись в %s: %v", filepath.Dir(u.Exe), err)
	}
	f.Close()
	return os.Remove(f.Name())
}

// Check возвращает сведения о последнем релизе (результат кэшируется на 10 минут).
func (u *Updater) Check(ctx context.Context, force bool) Info {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.Enabled {
		i := u.base()
		i.Error = "проверка обновлений отключена в конфигурации (update_check: false)"
		return i
	}
	if !force && !u.cached.CheckedAt.IsZero() && time.Since(u.cached.CheckedAt) < cacheTTL {
		i := u.cached
		i.HasBackup = u.base().HasBackup
		return i
	}
	i := u.base()
	i.CheckedAt = time.Now()
	fail := func(err error) Info {
		i.Error = err.Error()
		u.cached, u.rel = i, nil
		return i
	}
	if !repoRe.MatchString(u.Repo) {
		return fail(errors.New("некорректный update_repo"))
	}
	resp, err := u.get(ctx, u.APIBase+"/repos/"+u.Repo+"/releases/latest", 1<<20, "application/vnd.github+json")
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	var rel release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&rel); err != nil {
		return fail(fmt.Errorf("ответ GitHub не разобран: %w", err))
	}
	i.Latest = strings.TrimPrefix(rel.Tag, "v")
	i.Notes, i.URL, i.Published = rel.Body, rel.HTMLURL, rel.Published
	if _, ok := parseSemver(rel.Tag); !ok {
		return fail(fmt.Errorf("тег релиза %q не похож на версию", rel.Tag))
	}
	i.Available = newer(rel.Tag, Current)
	switch {
	case !i.Available:
	case func() bool { _, err := assetName(); return err != nil }():
		_, err := assetName()
		i.Reason = err.Error()
	default:
		if err := u.canWrite(); err != nil {
			i.Reason = err.Error()
		} else if rel.Draft || rel.Prerelease {
			i.Reason = "релиз помечен как черновик/пререлиз"
		} else {
			i.CanApply = true
		}
	}
	u.cached, u.rel = i, &rel
	return i
}

// ---------- установка ----------

// Apply скачивает и устанавливает последнюю версию. Перезапуск выполняет вызывающий код.
func (u *Updater) Apply(ctx context.Context, w io.Writer, dryRun bool) (string, error) {
	info := u.Check(ctx, true)
	if info.Error != "" {
		return "", errors.New(info.Error)
	}
	if !info.Available {
		return "", errors.New("установлена последняя версия")
	}
	if !info.CanApply {
		return "", fmt.Errorf("обновление недоступно: %s", info.Reason)
	}
	u.mu.Lock()
	rel := u.rel
	u.mu.Unlock()
	if rel == nil {
		return "", errors.New("нет данных о релизе")
	}
	name, _ := assetName()
	var binURL, sumURL string
	var binSize int64
	for _, a := range rel.Assets {
		switch a.Name {
		case name:
			binURL, binSize = a.URL, a.Size
		case name + ".sha256":
			sumURL = a.URL
		}
	}
	if binURL == "" {
		return "", fmt.Errorf("в релизе %s нет файла %s", rel.Tag, name)
	}
	if sumURL == "" {
		return "", fmt.Errorf("в релизе %s нет файла контрольной суммы %s.sha256 — обновление отменено", rel.Tag, name)
	}
	if binSize > maxBinary {
		return "", errors.New("бинарник слишком большой")
	}
	fmt.Fprintf(w, "→ Обновление %s → %s\n", Current, info.Latest)
	if dryRun {
		fmt.Fprintf(w, "(dry-run) скачал бы %s и заменил %s\n", binURL, u.Exe)
		return info.Latest, nil
	}

	fmt.Fprintln(w, "→ Скачиваю контрольную сумму")
	sresp, err := u.get(ctx, sumURL, 1<<10, "")
	if err != nil {
		return "", err
	}
	sb, err := io.ReadAll(io.LimitReader(sresp.Body, 1024))
	sresp.Body.Close()
	if err != nil {
		return "", err
	}
	want := strings.ToLower(strings.Fields(string(sb) + " ")[0])
	if len(want) != 64 {
		return "", errors.New("файл контрольной суммы повреждён")
	}

	fmt.Fprintf(w, "→ Скачиваю %s\n", name)
	resp, err := u.get(ctx, binURL, maxBinary, "application/octet-stream")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	tmp, err := os.CreateTemp(filepath.Dir(u.Exe), ".goserverpanel-new-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, maxBinary+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil && n > maxBinary {
		err = errors.New("бинарник слишком большой")
	}
	if err != nil {
		cleanup()
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		cleanup()
		return "", fmt.Errorf("контрольная сумма не совпала (ожидалась %s…, получена %s…) — файл не установлен", want[:12], got[:12])
	}
	fmt.Fprintf(w, "✓ Контрольная сумма совпала (%d КБ)\n", n>>10)

	if err := os.Chmod(tmpName, 0o755); err != nil {
		cleanup()
		return "", err
	}
	fmt.Fprintln(w, "→ Проверяю запуск новой версии")
	cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	out, err := exec.CommandContext(cctx, tmpName, "-version").CombinedOutput()
	cancel()
	if err != nil {
		cleanup()
		return "", fmt.Errorf("новый бинарник не запускается: %v", err)
	}
	if !strings.Contains(string(out), info.Latest) {
		cleanup()
		return "", fmt.Errorf("версия бинарника (%s) не совпадает с релизом %s", strings.TrimSpace(string(out)), info.Latest)
	}

	fmt.Fprintln(w, "→ Заменяю бинарник (прежняя версия сохранена как .bak)")
	bak := u.bakPath()
	_ = os.Remove(bak)
	if err := os.Rename(u.Exe, bak); err != nil {
		cleanup()
		return "", err
	}
	if err := os.Rename(tmpName, u.Exe); err != nil {
		_ = os.Rename(bak, u.Exe) // вернуть как было
		cleanup()
		return "", err
	}
	u.mu.Lock()
	u.cached = Info{}
	u.mu.Unlock()
	return info.Latest, nil
}

// Rollback возвращает предыдущую версию из .bak. Перезапуск выполняет вызывающий код.
func (u *Updater) Rollback() error {
	bak := u.bakPath()
	if _, err := os.Stat(bak); err != nil {
		return errors.New("резервной копии нет — откатываться некуда")
	}
	if out, err := exec.Command(bak, "-version").CombinedOutput(); err != nil {
		return fmt.Errorf("резервная копия не запускается: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	if err := os.Rename(bak, u.Exe); err != nil {
		return err
	}
	u.mu.Lock()
	u.cached = Info{}
	u.mu.Unlock()
	return nil
}

// Restart заменяет текущий процесс новым бинарником (тот же PID, сокеты закрываются при exec).
func (u *Updater) Restart() error {
	return syscall.Exec(u.Exe, os.Args, os.Environ())
}
