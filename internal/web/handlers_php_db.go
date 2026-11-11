package web

import (
	"context"
	"io"
	"net/http"
	"os"
	"strings"

	"goserverpanel/internal/databases"
	"goserverpanel/internal/php"
)

// ---------- PHP ----------

func (a *App) handlePHPVersions(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.PHP.Versions())
}

func (a *App) jobResp(w http.ResponseWriter, id string) {
	writeJSON(w, 202, map[string]any{"job": id})
}

func (a *App) handlePHPInstall(w http.ResponseWriter, r *http.Request) {
	ver := r.PathValue("ver")
	if !php.VerRe.MatchString(ver) {
		fail(w, 400, "некорректная версия")
		return
	}
	j := a.Jobs.Start("Установка PHP "+ver, func(ctx context.Context, w io.Writer) error { return a.PHP.Install(ctx, w, ver) })
	a.audit(r, "php.install", ver)
	a.jobResp(w, j.ID)
}

func (a *App) handlePHPModules(w http.ResponseWriter, r *http.Request) {
	mods, err := a.PHP.Modules(r.Context(), r.PathValue("ver"))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, mods)
}

func (a *App) handlePHPModuleAction(w http.ResponseWriter, r *http.Request) {
	ver, name, action := r.PathValue("ver"), r.PathValue("name"), r.PathValue("action")
	if !php.VerRe.MatchString(ver) || !php.ModRe.MatchString(name) {
		fail(w, 400, "некорректные параметры")
		return
	}
	switch action {
	case "install", "remove", "enable", "disable":
	default:
		fail(w, 400, "неизвестное действие")
		return
	}
	j := a.Jobs.Start("PHP "+ver+": "+action+" "+name, func(ctx context.Context, w io.Writer) error {
		return a.PHP.ModuleAction(ctx, w, ver, name, action)
	})
	a.audit(r, "php.module."+action, ver+"/"+name)
	a.jobResp(w, j.ID)
}

func (a *App) handlePHPIniGet(w http.ResponseWriter, r *http.Request) {
	vals, err := a.PHP.ReadIni(r.PathValue("ver"))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"values": vals, "keys": php.IniKeys})
}

func (a *App) handlePHPIniPut(w http.ResponseWriter, r *http.Request) {
	var in struct{ Values map[string]string }
	if !decode(w, r, &in) {
		return
	}
	clean := map[string]string{}
	for k, v := range in.Values {
		if strings.TrimSpace(v) != "" {
			clean[k] = strings.TrimSpace(v)
		}
	}
	if err := a.PHP.WriteIni(r.Context(), r.PathValue("ver"), clean); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.audit(r, "php.ini", r.PathValue("ver"))
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------- базы данных ----------

func (a *App) handleDBStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.DB.Status())
}

func (a *App) handleDBList(w http.ResponseWriter, r *http.Request) {
	l, err := a.DB.ListDatabases(r.Context(), r.PathValue("engine"))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, l)
}

func (a *App) handleDBUsers(w http.ResponseWriter, r *http.Request) {
	l, err := a.DB.ListUsers(r.Context(), r.PathValue("engine"))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, l)
}

func (a *App) handleDBCreate(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("engine")
	var in struct{ Name, Collation, User, Password string }
	if !decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	pass := in.Password
	if in.User != "" {
		if pass == "" {
			pass = databases.GeneratePassword()
		}
		if err := a.DB.CreateUser(ctx, eng, in.User, pass); err != nil {
			fail(w, 400, err.Error())
			return
		}
	}
	if err := a.DB.CreateDatabase(ctx, eng, in.Name, in.Collation, in.User); err != nil {
		if in.User != "" {
			_ = a.DB.DropUser(ctx, eng, in.User)
		}
		fail(w, 400, err.Error())
		return
	}
	if in.User != "" {
		if err := a.DB.Grant(ctx, eng, in.Name, in.User); err != nil {
			fail(w, 500, err.Error())
			return
		}
	}
	a.audit(r, "db.create", eng+"/"+in.Name)
	res := map[string]any{"name": in.Name}
	if in.User != "" {
		res["user"], res["password"] = in.User, pass
	}
	writeJSON(w, 201, res)
}

func (a *App) handleDBDrop(w http.ResponseWriter, r *http.Request) {
	if err := a.DB.DropDatabase(r.Context(), r.PathValue("engine"), r.PathValue("name")); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.audit(r, "db.drop", r.PathValue("engine")+"/"+r.PathValue("name"))
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleDBUserCreate(w http.ResponseWriter, r *http.Request) {
	eng := r.PathValue("engine")
	var in struct{ Name, Password string }
	if !decode(w, r, &in) {
		return
	}
	if in.Password == "" {
		in.Password = databases.GeneratePassword()
	}
	if err := a.DB.CreateUser(r.Context(), eng, in.Name, in.Password); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.audit(r, "db.user.create", eng+"/"+in.Name)
	writeJSON(w, 201, map[string]any{"name": in.Name, "password": in.Password})
}

func (a *App) handleDBUserDrop(w http.ResponseWriter, r *http.Request) {
	if err := a.DB.DropUser(r.Context(), r.PathValue("engine"), r.PathValue("name")); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.audit(r, "db.user.drop", r.PathValue("engine")+"/"+r.PathValue("name"))
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleDBGrant(w http.ResponseWriter, r *http.Request) {
	var in struct{ DB, User string }
	if !decode(w, r, &in) {
		return
	}
	if err := a.DB.Grant(r.Context(), r.PathValue("engine"), in.DB, in.User); err != nil {
		fail(w, 400, err.Error())
		return
	}
	a.audit(r, "db.grant", in.User+" → "+in.DB)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleDBBackup(w http.ResponseWriter, r *http.Request) {
	eng, name := r.PathValue("engine"), r.PathValue("name")
	if !databases.ValidIdent(name) {
		fail(w, 400, "некорректное имя БД")
		return
	}
	j := a.Jobs.Start("Бэкап "+eng+"/"+name, func(ctx context.Context, w io.Writer) error {
		f, err := a.DB.Backup(ctx, w, eng, name)
		if err == nil {
			io.WriteString(w, "Файл: "+f+"\n")
		}
		return err
	})
	a.audit(r, "db.backup", eng+"/"+name)
	a.jobResp(w, j.ID)
}

func (a *App) handleDBRestore(w http.ResponseWriter, r *http.Request) {
	eng, name := r.PathValue("engine"), r.PathValue("name")
	var in struct{ File string }
	if !decode(w, r, &in) {
		return
	}
	if !databases.ValidIdent(name) {
		fail(w, 400, "некорректное имя БД")
		return
	}
	if _, err := a.DB.BackupPath(in.File); err != nil {
		fail(w, 400, err.Error())
		return
	}
	j := a.Jobs.Start("Восстановление "+eng+"/"+name, func(ctx context.Context, w io.Writer) error {
		return a.DB.Restore(ctx, w, eng, name, in.File)
	})
	a.audit(r, "db.restore", eng+"/"+name+" ← "+in.File)
	a.jobResp(w, j.ID)
}

func (a *App) handleDBBackups(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, a.DB.ListBackups())
}

func (a *App) handleDBBackupDownload(w http.ResponseWriter, r *http.Request) {
	p, err := a.DB.BackupPath(r.PathValue("file"))
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	f, err := os.Open(p)
	if err != nil {
		fail(w, 404, "файл не найден")
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+r.PathValue("file")+`"`)
	io.Copy(w, f)
}
