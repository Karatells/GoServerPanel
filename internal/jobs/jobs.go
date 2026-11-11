// Package jobs — фоновые задачи с потоковым выводом (apt, установка CMS, бэкапы).
package jobs

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"goserverpanel/internal/store"
)

const maxBuf = 512 * 1024

type Job struct {
	ID       string
	Name     string
	mu       sync.Mutex
	status   string // running | done | failed
	err      string
	buf      []byte
	subs     map[chan []byte]struct{}
	started  time.Time
	finished time.Time
	done     chan struct{}
}

type View struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Status   string    `json:"status"`
	Error    string    `json:"error,omitempty"`
	Output   string    `json:"output"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitempty"`
}

func (j *Job) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.buf = append(j.buf, p...)
	if len(j.buf) > maxBuf {
		j.buf = j.buf[len(j.buf)-maxBuf/2:]
	}
	cp := append([]byte(nil), p...)
	for ch := range j.subs {
		select {
		case ch <- cp:
		default: // медленный подписчик не должен блокировать задачу
		}
	}
	return len(p), nil
}

func (j *Job) View() View {
	j.mu.Lock()
	defer j.mu.Unlock()
	return View{ID: j.ID, Name: j.Name, Status: j.status, Error: j.err, Output: string(j.buf), Started: j.started, Finished: j.finished}
}

// Subscribe возвращает накопленный вывод и канал новых фрагментов.
func (j *Job) Subscribe() (initial []byte, ch chan []byte, cancel func(), done <-chan struct{}) {
	j.mu.Lock()
	defer j.mu.Unlock()
	ch = make(chan []byte, 256)
	if j.subs == nil {
		j.subs = map[chan []byte]struct{}{}
	}
	j.subs[ch] = struct{}{}
	initial = append([]byte(nil), j.buf...)
	return initial, ch, func() {
		j.mu.Lock()
		delete(j.subs, ch)
		j.mu.Unlock()
	}, j.done
}

type Manager struct {
	mu   sync.Mutex
	jobs map[string]*Job
}

func New() *Manager { return &Manager{jobs: map[string]*Job{}} }

func (m *Manager) Get(id string) *Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.jobs[id]
}

// Start запускает fn в фоне. Контекст не связан с HTTP-запросом.
func (m *Manager) Start(name string, fn func(ctx context.Context, w io.Writer) error) *Job {
	j := &Job{ID: store.NewID(), Name: name, status: "running", started: time.Now(), done: make(chan struct{})}
	m.mu.Lock()
	for id, o := range m.jobs { // чистка старых завершённых
		if o.status != "running" && time.Since(o.finished) > time.Hour {
			delete(m.jobs, id)
		}
	}
	m.jobs[j.ID] = j
	m.mu.Unlock()
	go func() {
		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("panic: %v", r)
				}
			}()
			return fn(context.Background(), j)
		}()
		j.mu.Lock()
		j.finished = time.Now()
		if err != nil {
			j.status, j.err = "failed", err.Error()
		} else {
			j.status = "done"
		}
		j.mu.Unlock()
		if err != nil {
			fmt.Fprintf(j, "\n✗ Ошибка: %v\n", err)
		} else {
			fmt.Fprintf(j, "\n✓ Готово\n")
		}
		close(j.done)
	}()
	return j
}
