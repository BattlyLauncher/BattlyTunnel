package tunnel

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Server struct {
	config              ServerConfig
	tls                 *tls.Config
	auth                Authorizer
	mu                  sync.Mutex
	sessions            map[string]*session
	peers               map[net.Conn]struct{}
	handshakes          chan struct{}
	connections         chan struct{}
	wg                  sync.WaitGroup
	authorizationDenied atomic.Uint64
	registrationDenied  atomic.Uint64
	authSlots           chan struct{}
}

// Stats deliberately excludes account IDs, capabilities and tokens.
type Stats struct {
	Event               string `json:"event"`
	Sessions            int    `json:"sessions"`
	Streams             int    `json:"streams"`
	Handshakes          int    `json:"handshakes"`
	AuthorizationDenied uint64 `json:"authorizationDenied"`
	RegistrationDenied  uint64 `json:"registrationDenied"`
}

func (s *Server) Stats() Stats {
	s.mu.Lock()
	sessions := len(s.sessions)
	s.mu.Unlock()
	return Stats{"stats", sessions, len(s.connections), len(s.handshakes), s.authorizationDenied.Load(), s.registrationDenied.Load()}
}

type pendingStream struct {
	socket chan net.Conn
	done   chan struct{}
}
type session struct {
	server                  *Server
	id, secret, token, name string
	grant                   Authorization
	control                 *control
	listener                net.Listener
	ctx                     context.Context
	cancel                  context.CancelFunc
	once                    sync.Once
	mu                      sync.Mutex
	pending                 map[string]*pendingStream
	active                  map[net.Conn]struct{}
	slots                   chan struct{}
}

func NewServer(c ServerConfig, tc *tls.Config, auth Authorizer) (*Server, error) {
	c.Defaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if tc == nil || len(tc.Certificates) == 0 || auth == nil {
		return nil, errors.New("TLS certificate and authorizer required")
	}
	tc = tc.Clone()
	tc.MinVersion = tls.VersionTLS13
	tc.NextProtos = []string{alpn}
	s := &Server{config: c, tls: tc, auth: auth, sessions: make(map[string]*session), peers: make(map[net.Conn]struct{}), handshakes: make(chan struct{}, c.MaxHandshakes), connections: make(chan struct{}, c.MaxTotalConnections), authSlots: make(chan struct{}, 2*c.MaxAuthorizationsPerSecond)}
	for i := 0; i < cap(s.authSlots); i++ {
		s.authSlots <- struct{}{}
	}
	return s, nil
}

// Serve owns listener and all accepted sockets, and drains all workers on cancellation.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(time.Second / time.Duration(s.config.MaxAuthorizationsPerSecond))
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				select {
				case s.authSlots <- struct{}{}:
				default:
				}
			}
		}
	}()
	stop := context.AfterFunc(ctx, func() {
		_ = listener.Close()
		s.mu.Lock()
		for peer := range s.peers {
			_ = peer.Close()
		}
		all := make([]*session, 0, len(s.sessions))
		for _, ss := range s.sessions {
			all = append(all, ss)
		}
		s.mu.Unlock()
		for _, ss := range all {
			ss.close()
		}
	})
	defer stop()
	var result error
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				result = err
			}
			break
		}
		select {
		case s.handshakes <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		s.mu.Lock()
		s.peers[conn] = struct{}{}
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			defer func() { s.mu.Lock(); delete(s.peers, conn); s.mu.Unlock() }()
			s.handle(ctx, conn)
		}()
	}
	cancel()
	s.wg.Wait()
	return result
}
func (s *Server) handle(ctx context.Context, raw net.Conn) {
	released := false
	release := func() {
		if !released {
			<-s.handshakes
			released = true
		}
	}
	defer release()
	conn := tls.Server(raw, s.tls)
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if conn.HandshakeContext(ctx) != nil || conn.ConnectionState().NegotiatedProtocol != alpn {
		return
	}
	m, err := readFrame(conn)
	if err != nil {
		return
	}
	switch m.Type {
	case "hello":
		if !validToken(m.Token) || !validName.MatchString(m.Name) || m.Port < 0 || m.Port > 65535 {
			_ = writeFrame(conn, message{Type: "error", Error: "invalid_request"})
			return
		}
		select {
		case <-s.authSlots:
		default:
			_ = writeFrame(conn, message{Type: "error", Error: "rate_limited"})
			return
		}
		authctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		grant, err := s.auth.Authorize(authctx, m.Token, m.Name, m.Port)
		cancel()
		if err != nil {
			s.authorizationDenied.Add(1)
			_ = writeFrame(conn, message{Type: "error", Error: "authorization_denied"})
			return
		}
		ss, err := s.register(ctx, conn, m, grant)
		if err != nil {
			s.registrationDenied.Add(1)
			_ = writeFrame(conn, message{Type: "error", Error: "tunnel_unavailable"})
			return
		}
		defer ss.close()
		_ = conn.SetDeadline(time.Time{})
		if ss.control.send(message{Type: "registered", Session: ss.id, Secret: ss.secret, Port: grant.Port, Host: s.config.PublicHost, HeartbeatSeconds: s.config.HeartbeatSeconds, IdleSeconds: s.config.IdleSeconds, MaxStreams: s.config.MaxConnections}) != nil {
			return
		}
		release()
		s.wg.Add(2)
		go func() { defer s.wg.Done(); ss.accept() }()
		go func() { defer s.wg.Done(); ss.watch() }()
		for {
			_ = conn.SetReadDeadline(time.Now().Add(3 * seconds(s.config.HeartbeatSeconds)))
			msg, err := readFrame(conn)
			if err != nil || msg.Type != "pong" {
				return
			}
		}
	case "join":
		s.mu.Lock()
		ss := s.sessions[m.Session]
		s.mu.Unlock()
		if ss == nil || len(m.Secret) != 64 || subtle.ConstantTimeCompare([]byte(ss.secret), []byte(m.Secret)) != 1 {
			return
		}
		ss.mu.Lock()
		ch := ss.pending[m.Stream]
		if ch != nil && ss.ctx.Err() == nil {
			delete(ss.pending, m.Stream)
			ss.active[conn] = struct{}{}
		} else {
			ch = nil
		}
		ss.mu.Unlock()
		if ch == nil {
			return
		}
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		release()
		// Keep this worker alive until the session removes the data connection.
		if writeFrame(conn, message{Type: "joined"}) != nil {
			ss.untrack(conn)
			return
		}
		_ = conn.SetDeadline(time.Time{})
		select {
		case ch.socket <- conn:
		case <-ch.done:
			ss.untrack(conn)
			return
		case <-ss.ctx.Done():
			ss.untrack(conn)
			return
		}
		select {
		case <-ch.done:
		case <-ss.ctx.Done():
		}
	default:
		return
	}
}

func (s *Server) register(ctx context.Context, conn net.Conn, m message, g Authorization) (*session, error) {
	if g.UserID == "" || g.TunnelID == "" || g.Port < s.config.PortMin || g.Port > s.config.PortMax || (m.Port != 0 && g.Port != m.Port) {
		return nil, errors.New("invalid grant")
	}
	id, err := randomID()
	if err != nil {
		return nil, err
	}
	secret, err := randomID()
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	count := 0
	for _, old := range s.sessions {
		if old.grant.UserID == g.UserID {
			count++
		}
		if old.grant.TunnelID == g.TunnelID {
			return nil, errors.New("tunnel already connected")
		}
	}
	if len(s.sessions) >= s.config.MaxSessions || count >= s.config.MaxSessionsPerUser {
		return nil, errors.New("session quota exceeded")
	}
	listener, err := net.Listen("tcp", endpoint(s.config.PublicBind, g.Port))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	ss := &session{server: s, id: id, secret: secret, token: m.Token, name: m.Name, grant: g, control: &control{Conn: conn}, listener: listener, ctx: ctx, cancel: cancel, pending: make(map[string]*pendingStream), active: make(map[net.Conn]struct{}), slots: make(chan struct{}, s.config.MaxConnections)}
	s.sessions[id] = ss
	return ss, nil
}

func (ss *session) close() {
	ss.once.Do(func() {
		ss.cancel()
		_ = ss.listener.Close()
		_ = ss.control.Close()
		ss.mu.Lock()
		for conn := range ss.active {
			_ = closeNow(conn)
		}
		ss.mu.Unlock()
		ss.server.mu.Lock()
		delete(ss.server.sessions, ss.id)
		ss.server.mu.Unlock()
	})
}
func (ss *session) untrack(conn net.Conn) {
	_ = closeNow(conn)
	ss.mu.Lock()
	delete(ss.active, conn)
	ss.mu.Unlock()
}
func (ss *session) accept() {
	for {
		conn, err := ss.listener.Accept()
		if err != nil {
			return
		}
		select {
		case ss.slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		select {
		case ss.server.connections <- struct{}{}:
		default:
			<-ss.slots
			_ = conn.Close()
			continue
		}
		ss.mu.Lock()
		if ss.ctx.Err() != nil {
			ss.mu.Unlock()
			_ = conn.Close()
			<-ss.slots
			<-ss.server.connections
			return
		}
		ss.active[conn] = struct{}{}
		ss.mu.Unlock()
		ss.server.wg.Add(1)
		go func() {
			defer ss.server.wg.Done()
			defer func() { <-ss.slots; <-ss.server.connections; ss.untrack(conn) }()
			ss.forward(conn)
		}()
	}
}
func (ss *session) forward(public net.Conn) {
	id, err := randomID()
	if err != nil {
		return
	}
	ch := &pendingStream{socket: make(chan net.Conn), done: make(chan struct{})}
	ss.mu.Lock()
	ss.pending[id] = ch
	ss.mu.Unlock()
	defer func() { ss.mu.Lock(); delete(ss.pending, id); ss.mu.Unlock(); close(ch.done) }()
	if ss.control.send(message{Type: "open", Stream: id}) != nil {
		ss.close()
		return
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case data := <-ch.socket:
		defer ss.untrack(data)
		relay(public, data, seconds(ss.server.config.IdleSeconds))
	case <-timer.C:
	case <-ss.ctx.Done():
	}
}
func (ss *session) watch() {
	heartbeat := time.NewTicker(seconds(ss.server.config.HeartbeatSeconds))
	defer heartbeat.Stop()
	lease := time.NewTicker(seconds(ss.server.config.LeaseSeconds))
	defer lease.Stop()
	for {
		select {
		case <-ss.ctx.Done():
			return
		case <-heartbeat.C:
			if ss.control.send(message{Type: "ping"}) != nil {
				ss.close()
				return
			}
		case <-lease.C:
			ctx, cancel := context.WithTimeout(ss.ctx, 8*time.Second)
			g, err := ss.server.auth.Authorize(ctx, ss.token, ss.name, ss.grant.Port)
			cancel()
			if err != nil || g != ss.grant {
				ss.close()
				return
			}
		}
	}
}
