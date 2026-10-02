package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var validName = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(strings.ToLower(host), ".") {
		if !validName.MatchString(label) {
			return false
		}
	}
	return true
}

type ClientConfig struct {
	ServerAddr string `json:"serverAddr"`
	ServerPort int    `json:"serverPort"`
	Token      string `json:"token,omitempty"`
	CAFile     string `json:"caFile,omitempty"`
	ServerName string `json:"serverName,omitempty"`
	Proxies    []struct {
		Name       string `json:"name"`
		Type       string `json:"type"`
		LocalIP    string `json:"localIP"`
		LocalPort  int    `json:"localPort"`
		RemotePort int    `json:"remotePort"`
		Transport  struct {
			UseEncryption  bool `json:"useEncryption"`
			UseCompression bool `json:"useCompression"`
		} `json:"transport"`
	} `json:"proxies"`
}

func readConfig(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return errors.New("invalid configuration file")
	}
	d := json.NewDecoder(io.LimitReader(f, 64*1024+1))
	if err := d.Decode(value); err != nil {
		return errors.New("invalid configuration JSON")
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("unexpected configuration content")
	}
	return nil
}

func LoadClientConfig(path string) (ClientConfig, error) {
	var c ClientConfig
	if err := readConfig(path, &c); err != nil {
		return c, err
	}
	return c, c.Validate()
}

func validToken(token string) bool {
	return len(token) > 0 && len(token) <= 8192 && !strings.ContainsAny(token, "\r\n\x00")
}
func (c ClientConfig) Validate() error {
	if !validHost(c.ServerAddr) || (c.ServerName != "" && !validHost(c.ServerName)) || c.ServerPort < 1 || c.ServerPort > 65535 {
		return errors.New("invalid tunnel endpoint")
	}
	if !validToken(c.Token) {
		return errors.New("missing account token")
	}
	if len(c.Proxies) != 1 {
		return errors.New("exactly one TCP proxy is required")
	}
	p := c.Proxies[0]
	if !validName.MatchString(p.Name) || p.Type != "tcp" || p.LocalPort < 1 || p.LocalPort > 65535 || p.RemotePort < 0 || p.RemotePort > 65535 {
		return errors.New("invalid TCP proxy")
	}
	if p.LocalIP != "127.0.0.1" && p.LocalIP != "::1" && p.LocalIP != "localhost" {
		return errors.New("only a loopback Minecraft target is permitted")
	}
	if p.Transport.UseCompression || p.Transport.UseEncryption {
		return errors.New("FRP compression/encryption are unsupported; tunnel TLS is always enabled")
	}
	return nil
}

func (c ClientConfig) TLSConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, ServerName: c.ServerName, NextProtos: []string{alpn}, ClientSessionCache: tls.NewLRUClientSessionCache(32)}
	if cfg.ServerName == "" {
		cfg.ServerName = c.ServerAddr
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid CA file")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

type ServerConfig struct {
	MaxAuthorizationsPerSecond int    `json:"maxAuthorizationsPerSecond"`
	Listen                     string `json:"listen"`
	PublicBind                 string `json:"publicBind"`
	PublicHost                 string `json:"publicHost"`
	PortMin                    int    `json:"portMin"`
	PortMax                    int    `json:"portMax"`
	Certificate                string `json:"certificate"`
	Key                        string `json:"key"`
	AuthURL                    string `json:"authUrl,omitempty"`
	MaxSessions                int    `json:"maxSessions"`
	MaxSessionsPerUser         int    `json:"maxSessionsPerUser"`
	MaxConnections             int    `json:"maxConnectionsPerTunnel"`
	MaxHandshakes              int    `json:"maxHandshakes"`
	MaxTotalConnections        int    `json:"maxTotalConnections"`
	HeartbeatSeconds           int    `json:"heartbeatSeconds"`
	LeaseSeconds               int    `json:"leaseSeconds"`
	IdleSeconds                int    `json:"idleSeconds"`
}

func (c *ServerConfig) Defaults() {
	if c.MaxAuthorizationsPerSecond == 0 {
		c.MaxAuthorizationsPerSecond = 32
	}
	if c.Listen == "" {
		c.Listen = ":7001"
	}
	if c.PublicBind == "" {
		c.PublicBind = "0.0.0.0"
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = 512
	}
	if c.MaxSessionsPerUser == 0 {
		c.MaxSessionsPerUser = 4
	}
	if c.MaxConnections == 0 {
		c.MaxConnections = 128
	}
	if c.MaxHandshakes == 0 {
		c.MaxHandshakes = 128
	}
	if c.MaxTotalConnections == 0 {
		c.MaxTotalConnections = 2048
	}
	if c.HeartbeatSeconds == 0 {
		c.HeartbeatSeconds = 15
	}
	if c.LeaseSeconds == 0 {
		c.LeaseSeconds = 300
	}
	if c.IdleSeconds == 0 {
		c.IdleSeconds = 300
	}
}
func (c ServerConfig) Validate() error {
	if c.MaxAuthorizationsPerSecond < 1 || c.MaxAuthorizationsPerSecond > 1000 {
		return errors.New("invalid authorization rate limit")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return errors.New("invalid listen address")
	}
	if net.ParseIP(c.PublicBind) == nil {
		return errors.New("publicBind must be an IP address")
	}
	if !validHost(c.PublicHost) {
		return errors.New("missing public host")
	}
	if c.PortMin < 1024 || c.PortMax > 65535 || c.PortMin > c.PortMax {
		return errors.New("invalid public port range")
	}
	if c.MaxSessions < 1 || c.MaxSessions > 10000 || c.MaxSessionsPerUser < 1 || c.MaxSessionsPerUser > c.MaxSessions || c.MaxConnections < 1 || c.MaxConnections > 4096 || c.MaxHandshakes < 1 || c.MaxHandshakes > 4096 {
		return errors.New("invalid resource limits")
	}
	if c.MaxTotalConnections < 1 || c.MaxTotalConnections > 100000 {
		return errors.New("invalid total connection limit")
	}
	if c.HeartbeatSeconds < 1 || c.HeartbeatSeconds > 120 || c.LeaseSeconds < 1 || c.LeaseSeconds > 3600 || c.IdleSeconds < 1 || c.IdleSeconds > 86400 {
		return errors.New("invalid timeouts")
	}
	return nil
}
func LoadServerConfig(path string) (ServerConfig, error) {
	var c ServerConfig
	if err := readConfig(path, &c); err != nil {
		return c, err
	}
	c.Defaults()
	return c, c.Validate()
}

func endpoint(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }
func seconds(n int) time.Duration           { return time.Duration(n) * time.Second }
func safeError(code string) error           { return fmt.Errorf("tunnel: %s", code) }
