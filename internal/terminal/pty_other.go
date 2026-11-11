//go:build !linux

package terminal

import "errors"

type Session struct{}

func Start(shell string, cols, rows uint16) (*Session, error) {
	return nil, errors.New("терминал поддерживается только на Linux")
}
func (s *Session) Read(p []byte) (int, error)     { return 0, errors.New("unsupported") }
func (s *Session) Write(p []byte) (int, error)    { return 0, errors.New("unsupported") }
func (s *Session) Resize(cols, rows uint16) error { return errors.New("unsupported") }
func (s *Session) Close()                         {}
