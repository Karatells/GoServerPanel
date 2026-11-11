package web

import (
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"time"

	"goserverpanel/internal/auth"
	"goserverpanel/internal/terminal"
	"goserverpanel/internal/ws"
)

// ---------- терминал ----------

// handleTerminalToken — «step-up»: для доступа к терминалу нужно повторно подтвердить пароль (и TOTP).
func (a *App) handleTerminalToken(w http.ResponseWriter, r *http.Request) {
	if !a.Cfg.TerminalEnabled {
		fail(w, 403, "терминал отключён в конфигурации")
		return
	}
	ip := clientIP(r)
	if a.locked(ip) {
		fail(w, 429, "слишком много попыток, повторите позже")
		return
	}
	u := a.userFrom(r)
	var in struct{ Password, TOTP string }
	if !decode(w, r, &in) {
		return
	}
	if !auth.VerifyPassword(in.Password, u.PassHash) || (u.TOTPEnabled && !auth.VerifyTOTP(u.TOTPSecret, in.TOTP, time.Now())) {
		a.recordFail(ip)
		a.audit(r, "terminal.denied", "")
		fail(w, 403, "неверный пароль или код 2FA")
		return
	}
	tok := auth.RandomString(32)
	a.mu.Lock()
	now := time.Now()
	for k, g := range a.termToken {
		if now.After(g.exp) {
			delete(a.termToken, k)
		}
	}
	a.termToken[tok] = termGrant{userID: u.ID, exp: now.Add(30 * time.Second)}
	a.mu.Unlock()
	writeJSON(w, 200, map[string]any{"token": tok})
}

func (a *App) handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	if !a.Cfg.TerminalEnabled {
		fail(w, 403, "терминал отключён")
		return
	}
	tok := r.URL.Query().Get("token")
	a.mu.Lock()
	g, ok := a.termToken[tok]
	delete(a.termToken, tok) // одноразовый
	a.mu.Unlock()
	u := a.userFrom(r)
	if !ok || time.Now().After(g.exp) || g.userID != u.ID {
		fail(w, 403, "недействительный токен терминала")
		return
	}
	c, err := ws.Accept(w, r)
	if err != nil {
		return
	}
	defer c.Close()
	a.audit(r, "terminal.open", "")
	err = terminal.Serve(c, a.Cfg.Shell)
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	a.audit(r, "terminal.close", detail)
}

// ---------- файлы ----------

func (a *App) handleFilesList(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	if p == "" {
		// список разрешённых корней
		type root struct {
			Name  string `json:"name"`
			IsDir bool   `json:"is_dir"`
		}
		var out []root
		for _, rt := range a.Files.Roots {
			out = append(out, root{Name: rt, IsDir: true})
		}
		writeJSON(w, 200, map[string]any{"path": "", "roots": out, "entries": []any{}})
		return
	}
	ents, err := a.Files.List(p)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"path": filepath.Clean(p), "entries": ents})
}

func (a *App) handleFilesRead(w http.ResponseWriter, r *http.Request) {
	s, err := a.Files.Read(r.URL.Query().Get("path"))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"content": s})
}

func (a *App) handleFilesWrite(w http.ResponseWriter, r *http.Request) {
	var in struct{ Path, Content string }
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	if !decode(w, r, &in) {
		return
	}
	if err := a.Files.Write(in.Path, in.Content); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.audit(r, "file.write", in.Path)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleFilesMkdir(w http.ResponseWriter, r *http.Request) {
	var in struct{ Path string }
	if !decode(w, r, &in) {
		return
	}
	if err := a.Files.Mkdir(in.Path); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.audit(r, "file.mkdir", in.Path)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleFilesRename(w http.ResponseWriter, r *http.Request) {
	var in struct{ From, To string }
	if !decode(w, r, &in) {
		return
	}
	if err := a.Files.Rename(in.From, in.To); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.audit(r, "file.rename", in.From+" → "+in.To)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleFilesDelete(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	if err := a.Files.Delete(p); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.audit(r, "file.delete", p)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleFilesUpload(w http.ResponseWriter, r *http.Request) {
	dir := r.URL.Query().Get("dir")
	mr, err := r.MultipartReader()
	if err != nil {
		fail(w, 400, "ожидается multipart/form-data")
		return
	}
	n := 0
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			fail(w, 400, err.Error())
			return
		}
		if part.FileName() == "" {
			continue
		}
		if err := a.Files.Upload(dir, filepath.Base(part.FileName()), part); err != nil {
			fail(w, 400, err.Error())
			return
		}
		a.audit(r, "file.upload", filepath.Join(dir, filepath.Base(part.FileName())))
		n++
	}
	writeJSON(w, 200, map[string]any{"ok": true, "files": n})
}

func (a *App) handleFilesDownload(w http.ResponseWriter, r *http.Request) {
	f, st, err := a.Files.Open(r.URL.Query().Get("path"))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	defer f.Close()
	name := filepath.Base(st.Name())
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	http.ServeContent(w, r, name, st.ModTime(), f)
	a.audit(r, "file.download", r.URL.Query().Get("path"))
}
