package terminal

import (
	"encoding/json"
	"io"

	"goserverpanel/internal/ws"
)

// Serve связывает WebSocket с новой PTY-сессией и блокируется до её завершения.
// Бинарные кадры — ввод/вывод терминала; текстовые — JSON-команды {"type":"resize","cols":N,"rows":M}.
func Serve(conn *ws.Conn, shell string) error {
	sess, err := Start(shell, 80, 24)
	if err != nil {
		_ = conn.WriteText("\r\n\x1b[31mНе удалось запустить оболочку: " + err.Error() + "\x1b[0m\r\n")
		return err
	}
	defer sess.Close()

	done := make(chan struct{})
	go func() { // PTY → браузер
		defer close(done)
		buf := make([]byte, 8192)
		for {
			n, err := sess.Read(buf)
			if n > 0 {
				if werr := conn.WriteMessage(ws.OpBinary, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { // закрытие PTY → закрытие соединения
		<-done
		conn.Close()
	}()

	for { // браузер → PTY
		op, data, err := conn.ReadMessage()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		switch op {
		case ws.OpBinary:
			if _, err := sess.Write(data); err != nil {
				return err
			}
		case ws.OpText:
			var m struct {
				Type       string `json:"type"`
				Cols, Rows uint16
			}
			if json.Unmarshal(data, &m) == nil && m.Type == "resize" {
				_ = sess.Resize(m.Cols, m.Rows)
			}
		}
	}
}
