package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/BattlyLauncher/BattlyTunnel/internal/tunnel"
	"os"
	"os/signal"
	"syscall"
)

var version = "dev"

func main() {
	verifyCommand := len(os.Args) > 1 && os.Args[1] == "verify"
	if verifyCommand {
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}
	path := flag.String("c", "", "client JSON configuration")
	show := flag.Bool("version", false, "print version")
	verify := flag.Bool("verify", verifyCommand, "validate configuration without connecting")
	flag.Parse()
	if *show {
		fmt.Println("Battly Tunnel Client " + version)
		return
	}
	c, err := tunnel.LoadClientConfig(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid client configuration")
		os.Exit(1)
	}
	enc := json.NewEncoder(os.Stdout)
	client, err := tunnel.NewClient(c, func(e tunnel.Event) { _ = enc.Encode(e) })
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid TLS configuration")
		os.Exit(1)
	}
	if *verify {
		fmt.Println("Configuration valid")
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if client.Run(ctx) != nil {
		os.Exit(1)
	}
}
