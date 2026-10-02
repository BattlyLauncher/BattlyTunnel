package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/BattlyLauncher/BattlyTunnel/internal/tunnel"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	path := flag.String("c", "", "server JSON configuration")
	show := flag.Bool("version", false, "print version")
	flag.Parse()
	if *show {
		fmt.Println("Battly Tunnel Server " + version)
		return
	}
	c, err := tunnel.LoadServerConfig(*path)
	if err != nil {
		fail("Invalid server configuration")
	}
	cert, err := tls.LoadX509KeyPair(c.Certificate, c.Key)
	if err != nil {
		fail("Cannot load TLS certificate")
	}
	auth, err := tunnel.NewHTTPAuthorizer(c.AuthURL, os.Getenv("BATTLY_TUNNEL_AUTH_SECRET"))
	if err != nil {
		fail("Invalid authorization configuration")
	}
	server, err := tunnel.NewServer(c, &tls.Config{Certificates: []tls.Certificate{cert}}, auth)
	if err != nil {
		fail("Cannot initialize server")
	}
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		fail("Cannot bind tunnel listener")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fmt.Println("Battly Tunnel Server ready")
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		enc := json.NewEncoder(os.Stdout)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = enc.Encode(server.Stats())
			}
		}
	}()
	if server.Serve(ctx, listener) != nil {
		fail("Tunnel listener stopped unexpectedly")
	}
}
func fail(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
