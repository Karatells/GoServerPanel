// Package ws — минимальная серверная реализация WebSocket (RFC 6455) на stdlib.
package ws

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	OpText   = 1
	OpBinary = 2
	opClose  = 8
	opPing   = 9
	opPong   = 10

	maxMessage = 4 << 20
)

type Conn struct {
	c   net.Conn
	br  *bufio.Reader
	wmu sync.Mutex
}

// Accept выполняет рукопожатие. Origin должен совпадать с Host (защита от CSWSH).
func Accept(w http.ResponseWriter, r *http.Request) (*Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
		!strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") {
		http.Error(w, "websocket required", http.StatusBadRequest)
		return nil, errors.New("not a websocket request")
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			http.Error(w, "bad origin", http.StatusForbidden)
			return nil, errors.New("origin mismatch")
		}
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" || r.Header.Get("Sec-WebSocket-Version") != "13" {
		http.Error(w, "bad handshake", http.StatusBadRequest)
		return nil, errors.New("bad handshake")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return nil, errors.New("hijack unsupported")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " +
		base64.StdEncoding.EncodeToString(sum[:]) + "\r\n\r\n"
	if _, err := rw.WriteString(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		conn.Close()
		return nil, err
	}
	return &Conn{c: conn, br: rw.Reader}, nil
}

func (c *Conn) Close() error { return c.c.Close() }

func (c *Conn) SetReadDeadline(t time.Time) error { return c.c.SetReadDeadline(t) }

// ReadMessage читает целое сообщение (собирает фрагменты, отвечает на ping).
func (c *Conn) ReadMessage() (int, []byte, error) {
	var msg []byte
	var op int
	for {
		var h [2]byte
		if _, err := io.ReadFull(c.br, h[:]); err != nil {
			return 0, nil, err
		}
		fin := h[0]&0x80 != 0
		opcode := int(h[0] & 0x0f)
		masked := h[1]&0x80 != 0
		n := uint64(h[1] & 0x7f)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(c.br, b[:]); err != nil {
				return 0, nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(c.br, b[:]); err != nil {
				return 0, nil, err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		if !masked {
			return 0, nil, errors.New("client frame not masked")
		}
		if n > maxMessage || uint64(len(msg))+n > maxMessage {
			return 0, nil, errors.New("message too large")
		}
		var mask [4]byte
		if _, err := io.ReadFull(c.br, mask[:]); err != nil {
			return 0, nil, err
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return 0, nil, err
		}
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
		switch opcode {
		case opClose:
			_ = c.write(opClose, payload)
			return 0, nil, io.EOF
		case opPing:
			_ = c.write(opPong, payload)
		case opPong:
		case 0, OpText, OpBinary:
			if opcode != 0 {
				op = opcode
				msg = payload
			} else {
				msg = append(msg, payload...)
			}
			if fin {
				return op, msg, nil
			}
		default:
			return 0, nil, errors.New("unknown opcode")
		}
	}
}

func (c *Conn) WriteMessage(op int, data []byte) error { return c.write(op, data) }

func (c *Conn) WriteText(s string) error { return c.write(OpText, []byte(s)) }

func (c *Conn) Ping() error { return c.write(opPing, nil) }

func (c *Conn) write(op int, data []byte) error {
	hdr := []byte{0x80 | byte(op)}
	switch n := len(data); {
	case n < 126:
		hdr = append(hdr, byte(n))
	case n <= 0xffff:
		hdr = append(hdr, 126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 127, 0, 0, 0, 0, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := c.c.Write(append(hdr, data...)); err != nil {
		return err
	}
	return nil
}
