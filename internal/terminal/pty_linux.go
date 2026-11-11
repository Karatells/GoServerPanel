//go:build linux

// Package terminal: PTY-сессии оболочки, соединённые с WebSocket.
// PTY создаётся напрямую через /dev/ptmx и ioctl (без внешних зависимостей).
package terminal

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

type Session struct {
	ptmx *os.File
	cmd  *exec.Cmd
}

func ioctl(fd uintptr, req uintptr, arg unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg)); e != 0 {
		return e
	}
	return nil
}

type winsize struct{ Rows, Cols, X, Y uint16 }

func Start(shell string, cols, rows uint16) (*Session, error) {
	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	var n uint32
	if err := ioctl(ptmx.Fd(), syscall.TIOCGPTN, unsafe.Pointer(&n)); err != nil {
		ptmx.Close()
		return nil, err
	}
	var unlock int32
	if err := ioctl(ptmx.Fd(), syscall.TIOCSPTLCK, unsafe.Pointer(&unlock)); err != nil {
		ptmx.Close()
		return nil, err
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		ptmx.Close()
		return nil, err
	}
	defer slave.Close()

	s := &Session{ptmx: ptmx}
	if err := s.Resize(cols, rows); err != nil {
		ptmx.Close()
		return nil, err
	}
	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "COLORTERM=truecolor")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		ptmx.Close()
		return nil, err
	}
	s.cmd = cmd
	return s, nil
}

func (s *Session) Read(p []byte) (int, error)  { return s.ptmx.Read(p) }
func (s *Session) Write(p []byte) (int, error) { return s.ptmx.Write(p) }

func (s *Session) Resize(cols, rows uint16) error {
	if cols == 0 || rows == 0 || cols > 1000 || rows > 1000 {
		return errors.New("bad size")
	}
	ws := winsize{Rows: rows, Cols: cols}
	return ioctl(s.ptmx.Fd(), syscall.TIOCSWINSZ, unsafe.Pointer(&ws))
}

// Close завершает группу процессов оболочки и закрывает PTY.
func (s *Session) Close() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGHUP)
		_ = s.cmd.Process.Kill()
		go func() { _ = s.cmd.Wait() }()
	}
	_ = s.ptmx.Close()
}
