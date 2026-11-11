package web

import (
	"context"
	"io"
	"log"
	"net/http"
	"time"
)

func (a *App) handleUpdateInfo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.Upd.Check(r.Context(), false))
}

func (a *App) handleUpdateCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.Upd.Check(r.Context(), true))
}

// restartSoon перезапускает процесс через delay, чтобы клиент успел получить ответ/вывод задачи.
func (a *App) restartSoon(delay time.Duration) {
	if a.Cfg.DryRun {
		log.Printf("dry-run: перезапуск пропущен")
		return
	}
	go func() {
		time.Sleep(delay)
		log.Printf("перезапуск панели после обновления")
		if err := a.Upd.Restart(); err != nil {
			log.Printf("не удалось перезапустить процесс: %v — перезапустите службу вручную (systemctl restart goserverpanel)", err)
		}
	}()
}

func (a *App) handleUpdateApply(w http.ResponseWriter, r *http.Request) {
	info := a.Upd.Check(r.Context(), true)
	if info.Error != "" || !info.Available || !info.CanApply {
		msg := info.Error
		if msg == "" && !info.Available {
			msg = "установлена последняя версия"
		}
		if msg == "" {
			msg = info.Reason
		}
		fail(w, 400, msg)
		return
	}
	j := a.Jobs.Start("Обновление панели до "+info.Latest, func(ctx context.Context, w io.Writer) error {
		ver, err := a.Upd.Apply(ctx, w, a.Cfg.DryRun)
		if err != nil {
			return err
		}
		if !a.Cfg.DryRun {
			io.WriteString(w, "→ Перезапускаю панель, страница обновится автоматически…\n")
			a.restartSoon(2 * time.Second)
		}
		_ = ver
		return nil
	})
	a.audit(r, "update.apply", info.Current+" → "+info.Latest)
	a.jobResp(w, j.ID)
}

func (a *App) handleUpdateRollback(w http.ResponseWriter, r *http.Request) {
	if err := a.Upd.Rollback(); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.audit(r, "update.rollback", "")
	writeJSON(w, 200, map[string]any{"ok": true})
	a.restartSoon(1500 * time.Millisecond)
}
