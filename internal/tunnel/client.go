package tunnel

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// Event is the stable stdout contract consumed by Battly. It never includes credentials.
type Event struct {
	Event      string `json:"event"`
	RemotePort int    `json:"remotePort,omitempty"`
	PublicHost string `json:"publicHost,omitempty"`
	TunnelName string `json:"tunnelName,omitempty"`
	RetryInMS  int64  `json:"retryInMs,omitempty"`
}
type Client struct {
	config ClientConfig
	tls    *tls.Config
	emit   func(Event)
}

func NewClient(c ClientConfig, emit func(Event)) (*Client, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	tc, err := c.TLSConfig()
	if err != nil {
		return nil, err
	}
	return &Client{c, tc, emit}, nil
}
func (c *Client) event(e Event) {
	if c.emit != nil {
		c.emit(e)
	}
}
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}, Config: c.tls}
	conn, err := d.DialContext(ctx, "tcp", endpoint(c.config.ServerAddr, c.config.ServerPort))
	if err == nil && conn.(*tls.Conn).ConnectionState().NegotiatedProtocol != alpn {
		conn.Close()
		return nil, safeError("protocol_mismatch")
	}
	return conn, err
}
func (c *Client) Run(ctx context.Context) error {
	delay := time.Second
	for ctx.Err() == nil {
		started := time.Now()
		_ = c.runSession(ctx)
		if ctx.Err() != nil {
			break
		}
		if time.Since(started) > time.Minute {
			delay = time.Second
		}
		var b [8]byte
		_, _ = rand.Read(b[:])
		wait := delay/2 + time.Duration(binary.LittleEndian.Uint64(b[:])%uint64(delay/2+1))
		c.event(Event{Event: "reconnecting", RetryInMS: wait.Milliseconds()})
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		delay *= 2
		if delay > 30*time.Second {
			delay = 30 * time.Second
		}
	}
	c.event(Event{Event: "stopped"})
	return nil
}
func (c *Client) runSession(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer closeNow(conn)
	stop := context.AfterFunc(ctx, func() { closeNow(conn) })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	p := c.config.Proxies[0]
	if err = writeFrame(conn, message{Type: "hello", Token: c.config.Token, Name: p.Name, Port: p.RemotePort}); err != nil {
		return err
	}
	m, err := readFrame(conn)
	if err != nil {
		return err
	}
	if m.Type != "registered" || len(m.Session) != 64 || len(m.Secret) != 64 || m.Port < 1024 || m.Port > 65535 || (p.RemotePort != 0 && p.RemotePort != m.Port) || m.Host == "" {
		return safeError("registration_denied")
	}
	if m.HeartbeatSeconds < 1 || m.HeartbeatSeconds > 120 || m.IdleSeconds < 1 || m.IdleSeconds > 86400 || m.MaxStreams < 1 || m.MaxStreams > 4096 {
		return safeError("invalid_limits")
	}
	_ = conn.SetDeadline(time.Time{})
	c.event(Event{Event: "ready", RemotePort: m.Port, PublicHost: m.Host, TunnelName: p.Name})
	ctl := &control{Conn: conn}
	slots := make(chan struct{}, m.MaxStreams)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(3 * seconds(m.HeartbeatSeconds)))
		next, err := readFrame(conn)
		if err != nil {
			return err
		}
		switch next.Type {
		case "ping":
			if err = ctl.send(message{Type: "pong"}); err != nil {
				return err
			}
		case "open":
			if len(next.Stream) != 64 {
				return safeError("invalid_stream")
			}
			select {
			case slots <- struct{}{}:
			default:
				continue
			}
			wg.Add(1)
			go func(id string) { defer wg.Done(); defer func() { <-slots }(); c.stream(ctx, m, id) }(next.Stream)
		default:
			return safeError("invalid_control_message")
		}
	}
}
func (c *Client) stream(ctx context.Context, registration message, id string) {
	data, err := c.dial(ctx)
	if err != nil {
		return
	}
	defer closeNow(data)
	stop := context.AfterFunc(ctx, func() { closeNow(data) })
	defer stop()
	_ = data.SetDeadline(time.Now().Add(10 * time.Second))
	if writeFrame(data, message{Type: "join", Session: registration.Session, Secret: registration.Secret, Stream: id}) != nil {
		return
	}
	reply, err := readFrame(data)
	if err != nil || reply.Type != "joined" {
		return
	}
	_ = data.SetDeadline(time.Time{})
	p := c.config.Proxies[0]
	host := p.LocalIP
	if host == "localhost" {
		host = "127.0.0.1"
	} // Never let a hosts/DNS override turn the loopback target into an outbound proxy.
	local, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", endpoint(host, p.LocalPort))
	if err != nil {
		return
	}
	defer local.Close()
	localStop := context.AfterFunc(ctx, func() { local.Close() })
	defer localStop()
	relay(local, data, seconds(registration.IdleSeconds))
}
