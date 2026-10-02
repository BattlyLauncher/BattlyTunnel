package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testAuth struct {
	port    int
	revoked atomic.Bool
}

func (a *testAuth) Authorize(ctx context.Context, token, name string, requested int) (Authorization, error) {
	if a.revoked.Load() || token != "test-token" || name != "qa" || (requested != 0 && requested != a.port) {
		return Authorization{}, errors.New("denied")
	}
	return Authorization{UserID: "qa-user", TunnelID: "qa-tunnel", Port: a.port}, nil
}
func certificates(t testing.TB) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cp := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kd, _ := x509.MarshalECPrivateKey(key)
	kp := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	cert, err := tls.X509KeyPair(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(path, cp, 0600); err != nil {
		t.Fatal(err)
	}
	return cert, path
}
func freePort(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type harness struct {
	server                 *Server
	client                 *Client
	auth                   *testAuth
	addr                   string
	events                 chan Event
	stopServer, stopClient context.CancelFunc
	serverDone, clientDone chan error
	local                  net.Listener
	localWG                sync.WaitGroup
	sockets                sync.Map
}

func setup(t testing.TB, half bool) *harness {
	return setupWithConfig(t, half, nil)
}
func setupWithConfig(t testing.TB, half bool, configure func(*ServerConfig)) *harness {
	t.Helper()
	cert, ca := certificates(t)
	h := &harness{auth: &testAuth{port: freePort(t)}, events: make(chan Event, 100), serverDone: make(chan error, 1), clientDone: make(chan error, 1)}
	var err error
	h.local, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.localWG.Add(1)
	go func() {
		defer h.localWG.Done()
		for {
			conn, e := h.local.Accept()
			if e != nil {
				return
			}
			h.sockets.Store(conn, true)
			h.localWG.Add(1)
			go func() {
				defer h.localWG.Done()
				defer conn.Close()
				defer h.sockets.Delete(conn)
				if half {
					b, e := io.ReadAll(io.LimitReader(conn, 2<<20))
					if e == nil {
						_, _ = conn.Write(append([]byte("reply:"), b...))
					}
				} else {
					_, _ = io.Copy(conn, conn)
				}
			}()
		}
	}()
	c := ServerConfig{PublicBind: "127.0.0.1", PublicHost: "localhost", PortMin: h.auth.port, PortMax: h.auth.port, HeartbeatSeconds: 1, LeaseSeconds: 1}
	if configure != nil {
		configure(&c)
	}
	h.server, err = NewServer(c, &tls.Config{Certificates: []tls.Certificate{cert}}, h.auth)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.addr = listener.Addr().String()
	serverContext, stopServer := context.WithCancel(context.Background())
	h.stopServer = stopServer
	go func() { h.serverDone <- h.server.Serve(serverContext, listener) }()
	host, ps, _ := net.SplitHostPort(h.addr)
	port, _ := strconv.Atoi(ps)
	var cc ClientConfig
	_ = json.Unmarshal([]byte(`{"proxies":[{"name":"qa","type":"tcp","localIP":"127.0.0.1"}]}`), &cc)
	cc.ServerAddr = host
	cc.ServerPort = port
	cc.Token = "test-token"
	cc.CAFile = ca
	cc.Proxies[0].LocalPort = h.local.Addr().(*net.TCPAddr).Port
	cc.Proxies[0].RemotePort = h.auth.port
	h.client, err = NewClient(cc, func(e Event) {
		select {
		case h.events <- e:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	clientContext, stopClient := context.WithCancel(context.Background())
	h.stopClient = stopClient
	go func() { h.clientDone <- h.client.Run(clientContext) }()
	t.Cleanup(func() {
		h.stopClient()
		h.stopServer()
		h.local.Close()
		h.sockets.Range(func(k, v any) bool { k.(net.Conn).Close(); return true })
		for _, done := range []chan error{h.clientDone, h.serverDone} {
			select {
			case e := <-done:
				if e != nil {
					t.Error(e)
				}
			case <-time.After(5 * time.Second):
				t.Error("shutdown leaked a worker")
			}
		}
		h.localWG.Wait()
	})
	h.waitEvent(t, "ready")
	return h
}
func (h *harness) waitEvent(t testing.TB, want string) Event {
	t.Helper()
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case e := <-h.events:
			if e.Event == want {
				return e
			}
		case <-timer.C:
			t.Fatalf("missing event %s", want)
		}
	}
}
func (h *harness) dial(t testing.TB) net.Conn {
	t.Helper()
	c, e := net.DialTimeout("tcp", endpoint("127.0.0.1", h.auth.port), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	return c
}
func TestTunnelTCP(t *testing.T) {
	h := setup(t, false)
	payload := bytes.Repeat([]byte("Minecraft-data\x00\xff"), 65536)
	var wg sync.WaitGroup
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := h.dial(t)
			defer c.Close()
			writeDone := make(chan error, 1)
			go func() { _, e := c.Write(payload); writeDone <- e }()
			got := make([]byte, len(payload))
			_, e := io.ReadFull(c, got)
			if e != nil || !bytes.Equal(payload, got) {
				t.Errorf("TCP corruption: %v", e)
			}
			if e := <-writeDone; e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	// Completed streams must disappear while their control session remains alive.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		h.server.mu.Lock()
		peers := len(h.server.peers)
		h.server.mu.Unlock()
		if peers == 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("completed stream workers retained")
}
func TestHalfClose(t *testing.T) {
	h := setup(t, true)
	c := h.dial(t)
	defer c.Close()
	_, _ = c.Write([]byte("request"))
	if e := c.(*net.TCPConn).CloseWrite(); e != nil {
		t.Fatal(e)
	}
	reply, e := io.ReadAll(c)
	if e != nil || string(reply) != "reply:request" {
		t.Fatalf("half close: %q %v", reply, e)
	}
}
func TestReconnectAndRevocation(t *testing.T) {
	h := setup(t, false)
	h.server.mu.Lock()
	var old *session
	for _, ss := range h.server.sessions {
		old = ss
	}
	h.server.mu.Unlock()
	old.close()
	h.waitEvent(t, "reconnecting")
	h.waitEvent(t, "ready")
	c := h.dial(t)
	_, _ = c.Write([]byte("x"))
	b := make([]byte, 1)
	if _, e := io.ReadFull(c, b); e != nil {
		t.Fatal(e)
	}
	h.auth.revoked.Store(true)
	h.waitEvent(t, "reconnecting")
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, e := c.Read(b); e == nil {
		t.Fatal("revoked tunnel still carries traffic")
	}
	c.Close()
}
func TestTLSAndOwnership(t *testing.T) {
	h := setup(t, false)
	bad := h.client.config
	bad.CAFile = ""
	client, _ := NewClient(bad, nil)
	if c, e := client.dial(context.Background()); e == nil {
		c.Close()
		t.Fatal("untrusted certificate accepted")
	}
	conn, e := h.client.dial(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_ = writeFrame(conn, message{Type: "hello", Token: "wrong", Name: "qa", Port: h.auth.port})
	m, e := readFrame(conn)
	if e != nil || m.Type != "error" || m.Error != "authorization_denied" {
		t.Fatalf("unauthorized registration: %+v %v", m, e)
	}
	conn2, e := h.client.dial(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer conn2.Close()
	_ = conn2.SetDeadline(time.Now().Add(2 * time.Second))
	_ = writeFrame(conn2, message{Type: "join", Session: "unknown", Secret: string(bytes.Repeat([]byte("a"), 64)), Stream: "unknown"})
	if _, e = readFrame(conn2); e == nil {
		t.Fatal("unknown capability accepted")
	}
}

func TestStreamCapabilitiesAndReplay(t *testing.T) {
	h := setup(t, false)
	h.server.mu.Lock()
	var ss *session
	for _, s := range h.server.sessions {
		ss = s
	}
	h.server.mu.Unlock()
	id, _ := randomID()
	pending := &pendingStream{socket: make(chan net.Conn), done: make(chan struct{})}
	ss.mu.Lock()
	ss.pending[id] = pending
	ss.mu.Unlock()
	join := func(secret string) net.Conn {
		t.Helper()
		conn, e := h.client.dial(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if e = writeFrame(conn, message{Type: "join", Session: ss.id, Secret: secret, Stream: id}); e != nil {
			t.Fatal(e)
		}
		return conn
	}
	wrong := join(string(bytes.Repeat([]byte("z"), 64)))
	if _, e := readFrame(wrong); e == nil {
		t.Fatal("wrong stream capability accepted")
	}
	wrong.Close()
	valid := join(ss.secret)
	defer valid.Close()
	if m, e := readFrame(valid); e != nil || m.Type != "joined" {
		t.Fatalf("valid join denied: %v", e)
	}
	var data net.Conn
	select {
	case data = <-pending.socket:
	case <-time.After(2 * time.Second):
		t.Fatal("data not attached")
	}
	ss.untrack(data)
	close(pending.done)
	replay := join(ss.secret)
	defer replay.Close()
	if _, e := readFrame(replay); e == nil {
		t.Fatal("used stream capability accepted twice")
	}
}
func TestConnectionLimits(t *testing.T) {
	h := setupWithConfig(t, false, func(c *ServerConfig) { c.MaxConnections = 2; c.MaxTotalConnections = 2 })
	var active []net.Conn
	for i := 0; i < 2; i++ {
		c := h.dial(t)
		active = append(active, c)
		defer c.Close()
		_, _ = c.Write([]byte("x"))
		b := make([]byte, 1)
		if _, e := io.ReadFull(c, b); e != nil {
			t.Fatal(e)
		}
	}
	rejected := h.dial(t)
	defer rejected.Close()
	_, _ = rejected.Write([]byte("x"))
	b := make([]byte, 1)
	if _, e := rejected.Read(b); e == nil {
		t.Fatal("connection limit not enforced")
	}
	active[0].Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(h.server.connections) == 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	c := h.dial(t)
	defer c.Close()
	_, _ = c.Write([]byte("y"))
	if _, e := io.ReadFull(c, b); e != nil || b[0] != 'y' {
		t.Fatalf("connection slot not released: %v", e)
	}
}

func TestAuthorizationRateLimit(t *testing.T) {
	h := setupWithConfig(t, false, func(c *ServerConfig) { c.MaxAuthorizationsPerSecond = 1 })
	rateLimited := false
	for i := 0; i < 4; i++ {
		conn, e := h.client.dial(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		_ = writeFrame(conn, message{Type: "hello", Token: "wrong", Name: "qa", Port: h.auth.port})
		m, e := readFrame(conn)
		conn.Close()
		if e != nil {
			t.Fatal(e)
		}
		if m.Error == "rate_limited" {
			rateLimited = true
			break
		}
	}
	if !rateLimited {
		t.Fatal("authentication flood not rate limited")
	}
}

func TestDuplicateDoesNotStealTunnel(t *testing.T) {
	h := setup(t, false)
	conn, e := h.client.dial(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_ = writeFrame(conn, message{Type: "hello", Token: "test-token", Name: "qa", Port: h.auth.port})
	m, e := readFrame(conn)
	if e != nil || m.Type != "error" || m.Error != "tunnel_unavailable" {
		t.Fatalf("duplicate accepted: %+v %v", m, e)
	}
	c := h.dial(t)
	defer c.Close()
	_, _ = c.Write([]byte("x"))
	var b [1]byte
	if _, e = io.ReadFull(c, b[:]); e != nil || b[0] != 'x' {
		t.Fatal("original tunnel interrupted")
	}
	if h.server.Stats().RegistrationDenied != 1 {
		t.Fatal("registration rejection not counted")
	}
}

func TestServerRestart(t *testing.T) {
	h := setup(t, false)
	oldClient := h.dial(t)
	defer oldClient.Close()
	_, _ = oldClient.Write([]byte("x"))
	var b [1]byte
	if _, e := io.ReadFull(oldClient, b[:]); e != nil {
		t.Fatal(e)
	}
	h.stopServer()
	select {
	case e := <-h.serverDone:
		if e != nil {
			t.Fatal(e)
		}
		h.serverDone <- nil
	case <-time.After(5 * time.Second):
		t.Fatal("server did not drain")
	}
	h.waitEvent(t, "reconnecting")
	_ = oldClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, e := oldClient.Read(b[:]); e == nil {
		t.Fatal("old player connection survived server shutdown")
	}
	listener, e := net.Listen("tcp", h.addr)
	if e != nil {
		t.Fatal(e)
	}
	server, e := NewServer(h.server.config, h.server.tls, h.auth)
	if e != nil {
		listener.Close()
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.stopServer = cancel
	h.server = server
	h.serverDone = make(chan error, 1)
	done := h.serverDone
	go func() { done <- server.Serve(ctx, listener) }()
	if event := h.waitEvent(t, "ready"); event.RemotePort != h.auth.port {
		t.Fatal("public port changed after restart")
	}
	newClient := h.dial(t)
	defer newClient.Close()
	_, _ = newClient.Write([]byte("y"))
	if _, e = io.ReadFull(newClient, b[:]); e != nil || b[0] != 'y' {
		t.Fatalf("restart lost forwarding: %v", e)
	}
}

func TestShutdownWithStalledPeers(t *testing.T) {
	h := setup(t, false)
	payload := make([]byte, 8<<20)
	var writers sync.WaitGroup
	for i := 0; i < 16; i++ {
		c := h.dial(t)
		defer c.Close()
		writers.Add(1)
		go func() { defer writers.Done(); _, _ = io.Copy(c, bytes.NewReader(payload)) }()
	}
	time.Sleep(20 * time.Millisecond)
	h.stopServer()
	select {
	case e := <-h.serverDone:
		if e != nil {
			t.Fatal(e)
		}
		h.serverDone <- nil
	case <-time.After(3 * time.Second):
		t.Fatal("stalled peers blocked server shutdown")
	}
	done := make(chan struct{})
	go func() { writers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("stalled player writes not canceled")
	}
}
func BenchmarkTunnelRoundTrip(b *testing.B) {
	h := setup(b, false)
	c := h.dial(b)
	defer c.Close()
	payload := make([]byte, 32*1024)
	reply := make([]byte, len(payload))
	b.SetBytes(int64(len(payload) * 2))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		if _, e := c.Write(payload); e != nil {
			b.Fatal(e)
		}
		if _, e := io.ReadFull(c, reply); e != nil {
			b.Fatal(e)
		}
	}
}

func BenchmarkTunnelConnect(b *testing.B) {
	h := setup(b, false)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := h.dial(b)
		_, e := c.Write([]byte("x"))
		if e != nil {
			b.Fatal(e)
		}
		var p [1]byte
		if _, e = io.ReadFull(c, p[:]); e != nil {
			b.Fatal(e)
		}
		c.Close()
	}
}
func BenchmarkTunnelParallel(b *testing.B) {
	h := setup(b, false)
	b.SetBytes(64 * 1024)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		c := h.dial(b)
		defer c.Close()
		payload := make([]byte, 32*1024)
		reply := make([]byte, len(payload))
		for pb.Next() {
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			if _, e := c.Write(payload); e != nil {
				b.Error(e)
				return
			}
			if _, e := io.ReadFull(c, reply); e != nil {
				b.Error(e)
				return
			}
		}
	})
}
