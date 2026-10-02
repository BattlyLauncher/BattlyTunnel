package tunnel

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the actual compiled commands, JSON files, auth HTTP and public socket.
func TestCLIBinaries(t *testing.T) {
	dir := t.TempDir()
	cert, ca := certificates(t)
	key, _ := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	keyPath := filepath.Join(dir, "key.pem")
	if e := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: key}), 0600); e != nil {
		t.Fatal(e)
	}
	port := freePort(t)
	controlPort := freePort(t)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["token"] != "test-token" {
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("s", 32) {
			w.WriteHeader(403)
			return
		}
		_ = json.NewEncoder(w).Encode(Authorization{"qa-user", "qa-id", port})
	}))
	defer api.Close()
	local, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer local.Close()
	localDone := make(chan struct{})
	go func() {
		defer close(localDone)
		conn, e := local.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 1)
		if _, e = conn.Read(b); e == nil {
			_, _ = conn.Write(b)
		}
	}()
	serverConfig := ServerConfig{Listen: endpoint("127.0.0.1", controlPort), PublicBind: "127.0.0.1", PublicHost: "localhost", PortMin: port, PortMax: port, Certificate: ca, Key: keyPath, AuthURL: api.URL}
	raw, _ := json.Marshal(serverConfig)
	serverPath := filepath.Join(dir, "server.json")
	_ = os.WriteFile(serverPath, raw, 0600)
	raw, _ = json.Marshal(map[string]any{"serverAddr": "127.0.0.1", "serverPort": controlPort, "caFile": ca, "token": "test-token", "proxies": []map[string]any{{"name": "qa", "type": "tcp", "localIP": "127.0.0.1", "localPort": local.Addr().(*net.TCPAddr).Port, "remotePort": 0}}})
	clientPath := filepath.Join(dir, "client.json")
	_ = os.WriteFile(clientPath, raw, 0600)
	run := func(role, path string) <-chan string {
		t.Helper()
		binary := filepath.Join(dir, role+".exe")
		build := exec.Command("go", "build", "-o", binary, "../../cmd/battly-tunnel-"+role)
		if out, e := build.CombinedOutput(); e != nil {
			t.Fatalf("CLI build failed: %v %s", e, out)
		}
		if out, e := exec.Command(binary, "-version").Output(); e != nil || !strings.Contains(string(out), "Battly Tunnel") {
			t.Fatal("version command failed")
		}
		if role == "client" {
			if out, e := exec.Command(binary, "verify", "-c", path).CombinedOutput(); e != nil || !strings.Contains(string(out), "Configuration valid") {
				t.Fatalf("legacy verify command failed: %s %v", out, e)
			}
		}
		ctx, cancel := context.WithCancel(context.Background())
		cmd := exec.CommandContext(ctx, binary, "-c", path)
		cmd.Env = append(os.Environ(), "BATTLY_TUNNEL_AUTH_SECRET="+strings.Repeat("s", 32))
		stdout, e := cmd.StdoutPipe()
		if e != nil {
			t.Fatal(e)
		}
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		done := make(chan error, 1)
		lines := make(chan string, 16)
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				lines <- scanner.Text()
			}
			close(lines)
			done <- cmd.Wait()
		}()
		t.Cleanup(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("CLI did not terminate")
			}
		})
		return lines
	}
	wait := func(lines <-chan string, predicate func(string) bool) string {
		t.Helper()
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for {
			select {
			case s, ok := <-lines:
				if !ok {
					t.Fatal("CLI exited before ready")
				}
				if strings.Contains(s, "test-token") {
					t.Fatal("credential leaked")
				}
				if predicate(s) {
					return s
				}
			case <-timer.C:
				t.Fatal("CLI startup timed out")
			}
		}
	}
	wait(run("server", serverPath), func(s string) bool { return s == "Battly Tunnel Server ready" })
	line := wait(run("client", clientPath), func(s string) bool { return strings.Contains(s, `"event":"ready"`) })
	var event Event
	if e = json.Unmarshal([]byte(line), &event); e != nil || event.RemotePort != port {
		t.Fatalf("public port not returned: %s", line)
	}
	conn, e := net.DialTimeout("tcp", endpoint("127.0.0.1", port), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte("x"))
	b := make([]byte, 1)
	if _, e = conn.Read(b); e != nil || b[0] != 'x' {
		t.Fatalf("CLI TCP relay failed: %v", e)
	}
	select {
	case <-localDone:
	case <-time.After(5 * time.Second):
		t.Fatal("local target did not finish")
	}
}
