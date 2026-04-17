// Command ghost-server is the GHOST VPN server.
//
// It listens for TLS connections, authenticates clients via Noise IK inside
// HTTP/2, and bridges authenticated tunnel traffic to a TUN interface.
// Unauthenticated requests are reverse-proxied to a fallback website.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/bulbashenko/ghost/internal/auth"
	"github.com/bulbashenko/ghost/internal/camouflage"
	"github.com/bulbashenko/ghost/internal/config"
	"github.com/bulbashenko/ghost/internal/fallback"
	"github.com/bulbashenko/ghost/internal/mux"
	"github.com/bulbashenko/ghost/internal/transport"
	"github.com/bulbashenko/ghost/internal/tun"
	"github.com/bulbashenko/ghost/internal/version"
)

func main() {
	var (
		configPath  = flag.String("config", "/etc/ghost/server.yaml", "path to YAML config")
		showVersion = flag.Bool("version", false, "print version and exit")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn, error")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("ghost-server %s (protocol v%d)\n", version.Version, version.Protocol)
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
	cfg, err := config.LoadServer(*configPath)
	if err != nil {
		logger.Error("config load failed", "error", err)
		os.Exit(1)
	}
	logger.Info("config loaded", "listen", cfg.Listen, "fallback", cfg.FallbackTarget)

	// Decode server static keypair.
	privBytes, err := auth.DecodeKey(cfg.PrivateKey)
	if err != nil {
		logger.Error("decode private key", "error", err)
		os.Exit(1)
	}
	serverKP, err := auth.KeypairFromPrivate(privBytes)
	if err != nil {
		logger.Error("derive keypair", "error", err)
		os.Exit(1)
	}
	logger.Info("server identity", "public_key", auth.EncodeKey(serverKP.Public))

	// Build allowed client keys set.
	allowedClients := make(map[string]bool, len(cfg.AllowedClients))
	for _, k := range cfg.AllowedClients {
		allowedClients[k] = true
	}

	// Fallback reverse proxy.
	fb, err := fallback.New(cfg.FallbackTarget)
	if err != nil {
		logger.Error("fallback proxy", "error", err)
		os.Exit(1)
	}
	logger.Info("fallback target", "url", fb.Target().String())

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

	// Enable IP forwarding and NAT.
	subnet, err := tun.SubnetFromAddress(cfg.TUN.Address)
	if err != nil {
		logger.Error("parse subnet", "error", err)
		os.Exit(1)
	}
	if err := tun.EnableIPForward(); err != nil {
		logger.Warn("ip forwarding", "error", err)
	}
	if err := tun.SetupNAT(subnet); err != nil {
		logger.Warn("NAT setup", "error", err)
	}
	defer tun.CleanupNAT(subnet)

	// Auth callback for the camouflage layer.
	onAuth := func(msg1 []byte) ([]byte, io.ReadWriteCloser, error) {
		resp, err := auth.NewResponder(serverKP)
		if err != nil {
			return nil, nil, err
		}

		_, err = resp.ReadMessage(msg1)
		if err != nil {
			return nil, nil, err
		}

		// Check allowed clients list.
		if len(allowedClients) > 0 {
			clientPub := auth.EncodeKey(resp.PeerStatic())
			if !allowedClients[clientPub] {
				return nil, nil, fmt.Errorf("client not in allowed list")
			}
		}

		msg2, session, err := resp.WriteMessage(nil)
		if err != nil {
			return nil, nil, err
		}

		logger.Info("client authenticated",
			"client_pubkey", auth.EncodeKey(resp.PeerStatic()),
		)

		// Create two pipes for bidirectional data flow:
		//   pipe1: HTTP(write) → mux(read)   (client→server data)
		//   pipe2: mux(write) → HTTP(read)    (server→client data)
		pipe1R, pipe1W := io.Pipe() // HTTP writes, mux reads
		pipe2R, pipe2W := io.Pipe() // mux writes, HTTP reads

		_ = session // Session encryption will be wired for per-frame encrypt.

		// Mux on the tunnel side: reads from pipe1, writes to pipe2.
		muxRW := &pipeReadWriter{r: pipe1R, w: pipe2W}
		muxConn := mux.NewConn(muxRW, false, func(s *mux.Stream) {
			logger.Debug("tunnel stream opened", "stream_id", s.ID())
			if err := tun.Bridge(tunDev, s); err != nil {
				logger.Debug("bridge ended", "error", err)
			}
		})

		// HTTP side: writes to pipe1, reads from pipe2.
		httpRW := &pipeReadWriter{r: pipe2R, w: pipe1W}
		_ = muxConn // kept alive by goroutines

		return msg2, httpRW, nil
	}

	// Build HTTP handler stack.
	tunnelHandler := camouflage.TunnelHandler(onAuth, fb)
	router := camouflage.NewRouter(tunnelHandler, fb)
	h2handler := camouflage.NewServer(&camouflage.ServerConfig{
		Handler: router,
	})

	// TLS listener.
	ln, err := transport.Listen(&transport.ListenerConfig{
		ListenAddr: cfg.Listen,
		CertFile:   cfg.CertFile,
		KeyFile:    cfg.KeyFile,
	})
	if err != nil {
		logger.Error("listen", "error", err)
		os.Exit(1)
	}
	defer ln.Close()
	logger.Info("listening", "addr", ln.Addr().String())

	// Graceful shutdown.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	srv := &http.Server{Handler: h2handler}
	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		srv.Close()
	}()

	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		logger.Error("serve", "error", err)
		os.Exit(1)
	}
}

// pipeReadWriter combines an io.Reader and io.Writer into an io.ReadWriter.
type pipeReadWriter struct {
	r io.Reader
	w io.Writer
}

func (p *pipeReadWriter) Read(b []byte) (int, error)  { return p.r.Read(b) }
func (p *pipeReadWriter) Write(b []byte) (int, error)  { return p.w.Write(b) }
func (p *pipeReadWriter) Close() error {
	if c, ok := p.r.(io.Closer); ok {
		c.Close()
	}
	if c, ok := p.w.(io.Closer); ok {
		c.Close()
	}
	return nil
}
