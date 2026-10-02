package tunnel

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientConfiguration(t *testing.T) {
	var valid ClientConfig
	_ = json.Unmarshal([]byte(`{"serverAddr":"localhost","serverPort":7001,"token":"test-token","proxies":[{"name":"qa","type":"tcp","localIP":"127.0.0.1","localPort":25565,"remotePort":30001}]}`), &valid)
	if e := valid.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, target := range []string{"10.0.0.1", "example.com", "169.254.169.254"} {
		c := valid
		c.Proxies = append(c.Proxies[:0:0], valid.Proxies...)
		c.Proxies[0].LocalIP = target
		if c.Validate() == nil {
			t.Fatalf("non-loopback target accepted: %s", target)
		}
	}
	c := valid
	c.Token = "x\nAuthorization: evil"
	if c.Validate() == nil {
		t.Fatal("invalid credential accepted")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	for _, raw := range []string{`{} {}`, strings.Repeat(" ", 65537), `{"token":`} {
		_ = os.WriteFile(path, []byte(raw), 0600)
		if _, e := LoadClientConfig(path); e == nil {
			t.Fatal("invalid file accepted")
		}
	}
}
