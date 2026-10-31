// Command h1-server runs a HyperOne server: it fronts a real camouflage TLS
// site and tunnels traffic for clients that prove knowledge of the PSK.
package main

import (
	"flag"
	"log/slog"
	"net"
	"os"

	"github.com/Gloridust/HyperOne/config"
	"github.com/Gloridust/HyperOne/internal/relay"
)

func main() {
	cfgPath := flag.String("config", "config/server.json", "path to server config JSON")
	debug := flag.Bool("debug", false, "verbose logging")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, psk, err := config.LoadServer(*cfgPath)
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Error("listen", "addr", cfg.Listen, "err", err)
		os.Exit(1)
	}
	log.Info("hyperone server up", "listen", cfg.Listen, "camouflage", cfg.Camouflage)

	srv := relay.NewServer(relay.ServerConfig{
		PSK:        psk,
		Camouflage: cfg.Camouflage,
		Logger:     log,
	})
	if err := srv.Serve(ln); err != nil {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
