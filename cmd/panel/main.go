// GoServerPanel — легковесная панель управления веб-сервером.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"goserverpanel/internal/auth"
	"goserverpanel/internal/config"
	"goserverpanel/internal/pki"
	"goserverpanel/internal/store"
	"goserverpanel/internal/update"
	"goserverpanel/internal/web"
	"goserverpanel/ui"
)

func main() {
	// Явные права (0600/0700) на секреты заданы в коде; umask 022 нужен, чтобы каталоги сайтов
	// и CMS не создавались закрытыми для nginx/php-fpm, даже если служба запущена с UMask=0077.
	syscall.Umask(0o022)
	cfgPath := flag.String("config", "config.yaml", "путь к config.yaml")
	reset := flag.String("reset-password", "", "сбросить пароль пользователя (новый пароль будет выведен) и выйти")
	showVer := flag.Bool("version", false, "показать версию")
	flag.Parse()
	if *showVer {
		fmt.Println("goserverpanel", update.Current)
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatalf("data_dir: %v", err)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "panel.json"))
	if err != nil {
		log.Fatalf("store: %v", err)
	}

	if *reset != "" {
		pw := auth.RandomString(16)
		h, _ := auth.HashPassword(pw)
		err := st.Update(func(d *store.Data) error {
			for i := range d.Users {
				if strings.EqualFold(d.Users[i].Username, *reset) {
					d.Users[i].PassHash = h
					return nil
				}
			}
			return errors.New("пользователь не найден")
		})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Новый пароль для %s: %s\n", *reset, pw)
		return
	}

	bootstrapAdmin(cfg, st)

	if _, err := os.Stat(cfg.TLSCert); err != nil {
		hosts := []string{"localhost", "127.0.0.1", "::1"}
		if h, err := os.Hostname(); err == nil {
			hosts = append(hosts, h)
		}
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok {
					hosts = append(hosts, ipn.IP.String())
				}
			}
		}
		if err := pki.SelfSigned(cfg.TLSCert, cfg.TLSKey, hosts); err != nil {
			log.Fatalf("tls: %v", err)
		}
		log.Printf("создан самоподписанный сертификат панели: %s", cfg.TLSCert)
	}

	app, err := web.New(&cfg, st, ui.FS())
	if err != nil {
		log.Fatalf("init: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app.Mon.Start(ctx)
	app.FixSitePerms() // чинит права каталогов сайтов, созданных старыми версиями

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           app.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	go func() {
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()
	if cfg.DryRun {
		log.Printf("ВНИМАНИЕ: режим dry_run — изменяющие команды не выполняются")
	}
	log.Printf("GoServerPanel %s: https://%s", update.Current, cfg.Listen)
	if err := srv.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// bootstrapAdmin создаёт первого администратора со случайным паролем.
func bootstrapAdmin(cfg config.Config, st *store.Store) {
	var n int
	st.View(func(d *store.Data) { n = len(d.Users) })
	if n > 0 {
		return
	}
	pw := auth.RandomString(16)
	h, err := auth.HashPassword(pw)
	if err != nil {
		log.Fatal(err)
	}
	if err := st.Update(func(d *store.Data) error {
		d.Users = append(d.Users, store.User{ID: store.NewID(), Username: "admin", PassHash: h, Role: "admin", Created: time.Now()})
		return nil
	}); err != nil {
		log.Fatal(err)
	}
	f := filepath.Join(cfg.DataDir, "initial_admin_password")
	_ = os.WriteFile(f, []byte(pw+"\n"), 0o600)
	fmt.Printf("\n=====================================================\n Создан администратор:  admin\n Пароль:                %s\n (также сохранён в %s — удалите после входа)\n=====================================================\n\n", pw, f)
}
