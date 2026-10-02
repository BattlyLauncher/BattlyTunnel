package tunnel

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const protocolVersion = 1
const maxFrame = 16 * 1024
const alpn = "battly-tunnel/1"

// Only the control handshake is framed. Game bytes use an independent TLS TCP connection.
type message struct {
	Version          int    `json:"version"`
	Type             string `json:"type"`
	Token            string `json:"token,omitempty"`
	Name             string `json:"name,omitempty"`
	Port             int    `json:"port,omitempty"`
	Host             string `json:"host,omitempty"`
	Session          string `json:"session,omitempty"`
	Secret           string `json:"secret,omitempty"`
	Stream           string `json:"stream,omitempty"`
	Error            string `json:"error,omitempty"`
	HeartbeatSeconds int    `json:"heartbeatSeconds,omitempty"`
	IdleSeconds      int    `json:"idleSeconds,omitempty"`
	MaxStreams       int    `json:"maxStreams,omitempty"`
}

func writeFrame(w io.Writer, m message) error {
	m.Version = protocolVersion
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > maxFrame {
		return errors.New("frame too large")
	}
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(b)))
	for _, part := range [][]byte{size[:], b} {
		for len(part) > 0 {
			n, err := w.Write(part)
			if err != nil {
				return err
			}
			if n == 0 {
				return io.ErrShortWrite
			}
			part = part[n:]
		}
	}
	return nil
}

func readFrame(r io.Reader) (message, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return message{}, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n == 0 || n > maxFrame {
		return message{}, errors.New("invalid frame size")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return message{}, err
	}
	var m message
	if err := json.Unmarshal(b, &m); err != nil {
		return m, errors.New("invalid frame")
	}
	if m.Version != protocolVersion {
		return m, errors.New("unsupported protocol version")
	}
	return m, nil
}

func randomID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

type control struct {
	net.Conn
	mu sync.Mutex
}

// Cancellation must not wait for a TLS close-notify to a peer that no longer reads.
func closeNow(conn net.Conn) error {
	if secure, ok := conn.(*tls.Conn); ok {
		return secure.NetConn().Close()
	}
	return conn.Close()
}
func (c *control) Close() error { return closeNow(c.Conn) }

func (c *control) send(m message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	return writeFrame(c.Conn, m)
}

var buffers = sync.Pool{New: func() any { b := make([]byte, 32*1024); return &b }}

// Read/write deadlines bound stalled peers. TCP/TLS half-close preserves responses
// after a peer has finished sending (e.g. status/query-like request streams).
type timedReader struct {
	conn net.Conn
	idle time.Duration
}

func (r timedReader) Read(b []byte) (int, error) {
	if r.idle > 0 {
		_ = r.conn.SetReadDeadline(time.Now().Add(r.idle))
	}
	return r.conn.Read(b)
}

type timedWriter struct {
	conn net.Conn
	idle time.Duration
}

func (w timedWriter) Write(b []byte) (int, error) {
	if w.idle > 0 {
		_ = w.conn.SetWriteDeadline(time.Now().Add(w.idle))
	}
	return w.conn.Write(b)
}
func relay(a, b net.Conn, idle time.Duration) {
	defer closeNow(a)
	defer closeNow(b)
	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		buf := buffers.Get().(*[]byte)
		_, err := io.CopyBuffer(timedWriter{dst, idle}, timedReader{src, idle}, *buf)
		buffers.Put(buf)
		if err != nil {
			_ = closeNow(a)
			_ = closeNow(b)
		} else if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			if cw.CloseWrite() != nil {
				_ = closeNow(a)
				_ = closeNow(b)
			}
		}
		done <- struct{}{}
	}
	go copyOne(a, b)
	go copyOne(b, a)
	<-done
	<-done
}
