// Command h1-client runs a local SOCKS5 proxy that tunnels connections through
// a HyperOne server. Point a browser or system proxy at its listen address.
package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Gloridust/HyperOne/config"
	"github.com/Gloridust/HyperOne/internal/relay"
	"github.com/Gloridust/HyperOne/internal/socks"
)

func main() {
	cfgPath := flag.String("config", "config/client.json", "path to client config JSON")
	debug := flag.Bool("debug", false, "verbose logging")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, psk, err := config.LoadClient(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	client := relay.NewClient(relay.ClientConfig{
		Server: cfg.Server,
		SNI:    cfg.SNI,
		PSK:    psk,
	})

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Error("listen", "addr", cfg.Listen, "err", err)
		os.Exit(1)
	}
	log.Info("hyperone client up", "socks", cfg.Listen, "server", cfg.Server, "sni", cfg.SNI)

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Error("accept", "err", err)
			os.Exit(1)
		}
		go handle(client, c, log)
	}
}

func handle(client *relay.Client, local net.Conn, log *slog.Logger) {
	defer local.Close()

	target, err := socks.Handshake(local)
	if err != nil {
		log.Debug("socks handshake", "err", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	tunnel, err := client.Dial(ctx, target)
	cancel()
	if err != nil {
		log.Debug("tunnel dial", "target", target.String(), "err", err)
		return
	}
	defer tunnel.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(tunnel, local) }()
	go func() { defer wg.Done(); io.Copy(local, tunnel) }()
	wg.Wait()
}
