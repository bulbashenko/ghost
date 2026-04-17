// Command ghost-client is the GHOST VPN client.
//
// It connects to a ghost-server via TLS (uTLS Chrome fingerprint),
// authenticates with Noise IK inside HTTP/2, and bridges the tunnel
// to a local TUN interface.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/bulbashenko/ghost/internal/auth"
	"github.com/bulbashenko/ghost/internal/camouflage"
	"github.com/bulbashenko/ghost/internal/config"
	"github.com/bulbashenko/ghost/internal/mux"
	"github.com/bulbashenko/ghost/internal/transport"
	"github.com/bulbashenko/ghost/internal/tun"
	"github.com/bulbashenko/ghost/internal/version"
)

func main() {
	var (
		configPath  = flag.String("config", "/etc/ghost/client.yaml", "path to YAML config")
		showVersion = flag.Bool("version", false, "print version and exit")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn, error")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("ghost-client %s (protocol v%d)\n", version.Version, version.Protocol)
		return
	}

	// Logger.
	var lvl slog.Level
	switch *logLevel {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(logger)

	// Load config.
	cfg, err := config.LoadClient(*configPath)
	if err != nil {
		logger.Error("config load failed", "error", err)
		os.Exit(1)
	}
	logger.Info("config loaded", "server", cfg.ServerAddr)

	// Decode client static keypair.
	privBytes, err := auth.DecodeKey(cfg.PrivateKey)
	if err != nil {
		logger.Error("decode private key", "error", err)
		os.Exit(1)
	}
	clientKP, err := auth.KeypairFromPrivate(privBytes)
	if err != nil {
		logger.Error("derive keypair", "error", err)
		os.Exit(1)
	}
	logger.Info("client identity", "public_key", auth.EncodeKey(clientKP.Public))

	// Decode server public key.
	serverPub, err := auth.DecodeKey(cfg.ServerPublicKey)
	if err != nil {
		logger.Error("decode server public key", "error", err)
		os.Exit(1)
	}

	// Graceful shutdown context.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// TLS dial with uTLS fingerprint.
	logger.Info("connecting", "addr", cfg.ServerAddr, "fingerprint", cfg.Fingerprint)
	conn, err := transport.Dial(ctx, &transport.DialerConfig{
		ServerAddr:  cfg.ServerAddr,
		SNI:         cfg.SNI,
		Fingerprint: transport.Fingerprint(cfg.Fingerprint),
	})
	if err != nil {
		logger.Error("tls dial", "error", err)
		os.Exit(1)
	}
	defer conn.Close()

	state := conn.ConnectionState()
	logger.Info("tls connected",
		"version", fmt.Sprintf("%#x", state.Version),
		"alpn", state.NegotiatedProtocol,
		"server_name", state.ServerName,
	)

	// Noise IK handshake: build msg1.
	initiator, err := auth.NewInitiator(clientKP, serverPub)
	if err != nil {
		logger.Error("noise initiator", "error", err)
		os.Exit(1)
	}
	msg1, err := initiator.WriteMessage(nil)
	if err != nil {
		logger.Error("noise msg1", "error", err)
		os.Exit(1)
	}

	// HTTP/2 handshake: send msg1, receive msg2.
	sni := cfg.SNI
	if sni == "" {
		sni = cfg.ServerAddr
	}
	msg2, tunnelConn, err := camouflage.Handshake(ctx, conn, &camouflage.ClientConfig{
		Host: sni,
	}, msg1)
	if err != nil {
		logger.Error("tunnel handshake", "error", err)
		os.Exit(1)
	}
	defer tunnelConn.Close()

	// Process Noise msg2 → derive session.
	_, session, err := initiator.ReadMessage(msg2)
	if err != nil {
		logger.Error("noise msg2", "error", err)
		os.Exit(1)
	}
	_ = session // Session cipher will be wired for per-frame encryption.
	logger.Info("noise handshake complete")

	// TUN device.
	tunDev, err := tun.New(&tun.Config{
		Name:    cfg.TUN.Name,
		Address: cfg.TUN.Address,
		MTU:     cfg.TUN.MTU,
	})
	if err != nil {
		logger.Error("tun create", "error", err)
		os.Exit(1)
	}
	defer tunDev.Close()
	logger.Info("tun device created", "name", tunDev.Name(), "address", cfg.TUN.Address)

	// Mux over the tunnel connection.
	muxConn := mux.NewConn(tunnelConn, true, nil)
	defer muxConn.Close()

	// Open a stream for IP traffic.
	stream, err := muxConn.OpenStream()
	if err != nil {
		logger.Error("open stream", "error", err)
		os.Exit(1)
	}
	logger.Info("tunnel stream opened", "stream_id", stream.ID())

	// Bridge TUN ↔ mux stream.
	logger.Info("tunnel active — routing traffic through GHOST")

	bridgeErr := make(chan error, 1)
	go func() {
		bridgeErr <- tun.Bridge(tunDev, stream)
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-bridgeErr:
		if err != nil && err != io.EOF {
			logger.Error("bridge", "error", err)
		}
	}
}
