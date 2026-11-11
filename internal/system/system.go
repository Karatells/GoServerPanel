// Package system: мониторинг ресурсов (/proc) и управление службами (systemctl).
package system

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"goserverpanel/internal/execx"
)

type DiskInfo struct {
	Path  string `json:"path"`
	Total uint64 `json:"total"`
	Used  uint64 `json:"used"`
}

type Stats struct {
	Time      time.Time  `json:"time"`
	Hostname  string     `json:"hostname"`
	CPU       float64    `json:"cpu"`
	Load      [3]float64 `json:"load"`
	MemTotal  uint64     `json:"mem_total"`
	MemUsed   uint64     `json:"mem_used"`
	SwapTotal uint64     `json:"swap_total"`
	SwapUsed  uint64     `json:"swap_used"`
	Disks     []DiskInfo `json:"disks"`
	Uptime    int64      `json:"uptime"`
}

type ServiceStatus struct {
	Name   string `json:"name"`
	Active string `json:"active"` // active | inactive | failed | …
}

type Monitor struct {
	run       *execx.Runner
	diskPaths []string
	mu        sync.RWMutex
	cpu       float64
	prevIdle  uint64
	prevTotal uint64
}

func NewMonitor(run *execx.Runner, diskPaths []string) *Monitor {
	return &Monitor{run: run, diskPaths: diskPaths}
}

func (m *Monitor) Start(ctx context.Context) {
	m.sampleCPU()
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.sampleCPU()
			}
		}
	}()
}

func (m *Monitor) sampleCPU() {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return
	}
	var total, idle uint64
	for i, s := range fields[1:] {
		v, _ := strconv.ParseUint(s, 10, 64)
		total += v
		if i == 3 || i == 4 { // idle + iowait
			idle += v
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.prevTotal != 0 && total > m.prevTotal {
		dt, di := float64(total-m.prevTotal), float64(idle-m.prevIdle)
		m.cpu = (1 - di/dt) * 100
	}
	m.prevTotal, m.prevIdle = total, idle
}

func (m *Monitor) Snapshot() Stats {
	s := Stats{Time: time.Now()}
	s.Hostname, _ = os.Hostname()
	m.mu.RLock()
	s.CPU = m.cpu
	m.mu.RUnlock()
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		for i := 0; i < 3 && i < len(f); i++ {
			s.Load[i], _ = strconv.ParseFloat(f[i], 64)
		}
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			v, _ := strconv.ParseFloat(f[0], 64)
			s.Uptime = int64(v)
		}
	}
	mem := map[string]uint64{}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			k, v, ok := strings.Cut(sc.Text(), ":")
			if !ok {
				continue
			}
			n, _ := strconv.ParseUint(strings.Fields(v + " ")[0], 10, 64)
			mem[k] = n * 1024
		}
		f.Close()
	}
	s.MemTotal = mem["MemTotal"]
	s.MemUsed = s.MemTotal - mem["MemAvailable"]
	s.SwapTotal = mem["SwapTotal"]
	s.SwapUsed = s.SwapTotal - mem["SwapFree"]
	seen := map[string]bool{}
	for _, p := range m.diskPaths {
		var st syscall.Statfs_t
		if err := syscall.Statfs(p, &st); err != nil {
			continue
		}
		key := fmt.Sprint(st.Fsid)
		if seen[key] {
			continue
		}
		seen[key] = true
		total := st.Blocks * uint64(st.Bsize)
		s.Disks = append(s.Disks, DiskInfo{Path: p, Total: total, Used: total - st.Bavail*uint64(st.Bsize)})
	}
	return s
}

var serviceRe = regexp.MustCompile(`^(nginx|mysql|mysqld|mariadb|postgresql|redis-server|php\d\.\d-fpm)$`)

func ValidService(name string) bool { return serviceRe.MatchString(name) }

// Services возвращает статус установленных служб из списка кандидатов.
func (m *Monitor) Services(ctx context.Context, candidates []string) []ServiceStatus {
	out := []ServiceStatus{}
	if !execx.Exists("systemctl") {
		return out
	}
	for _, n := range candidates {
		if !ValidService(n) {
			continue
		}
		load, err := m.run.Query(ctx, "systemctl", "show", "-p", "LoadState", "--value", n+".service")
		if err != nil || strings.TrimSpace(load) != "loaded" {
			continue
		}
		act, _ := m.run.Query(ctx, "systemctl", "is-active", n+".service")
		out = append(out, ServiceStatus{Name: n, Active: strings.TrimSpace(act)})
	}
	return out
}

func (m *Monitor) ServiceAction(ctx context.Context, name, action string) (string, error) {
	if !ValidService(name) {
		return "", fmt.Errorf("служба %q не разрешена", name)
	}
	switch action {
	case "start", "stop", "restart", "reload":
	default:
		return "", fmt.Errorf("действие %q не разрешено", action)
	}
	return m.run.Do(ctx, execx.Opts{}, "systemctl", action, name+".service")
}
