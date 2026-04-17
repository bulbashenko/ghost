package camouflage

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

// ServerConfig configures the HTTP/2 camouflage server.
type ServerConfig struct {
	// Handler is the top-level HTTP handler (typically a *Router).
	Handler http.Handler

	// AllowH2C enables HTTP/2 cleartext (h2c) for testing without TLS.
	// Must be false in production.
	AllowH2C bool
}

// NewServer creates an http.Handler configured for HTTP/2.
//
// In production, the returned handler sits behind a TLS listener (from
// internal/transport) that negotiates ALPN "h2". The HTTP/2 server is
// configured with settings that match typical web servers to avoid
// fingerprinting on server-side HTTP/2 parameters.
//
// In tests, set AllowH2C=true to use HTTP/2 over cleartext (h2c), which
// avoids the need for TLS certificates.
func NewServer(cfg *ServerConfig) http.Handler {
	h2srv := &http2.Server{
		// Match nginx/cloudflare defaults to avoid HTTP/2 fingerprinting.
		MaxConcurrentStreams: 128,
		MaxReadFrameSize:    1 << 14, // 16KB, HTTP/2 default
	}

	handler := cfg.Handler

	if cfg.AllowH2C {
		// h2c wraps the handler to support HTTP/2 without TLS (for tests).
		handler = h2c.NewHandler(handler, h2srv)
	} else {
		// For TLS mode, configure the handler to support HTTP/2.
		// The actual TLS listener is managed by internal/transport.
		_ = http2.ConfigureServer(&http.Server{Handler: handler}, h2srv)
	}

	return handler
}

// Serve starts serving HTTP/2 on the given listener. This is a convenience
// wrapper that creates an *http.Server with the given handler and calls Serve.
// The listener should be a TLS listener from internal/transport (or a plain
// TCP listener for h2c tests).
func Serve(ln net.Listener, handler http.Handler) error {
	srv := &http.Server{
		Handler: handler,
	}
	return srv.Serve(ln)
}

// TunnelHandler processes authenticated tunnel requests (POST /api/v1/stream).
//
// The handshake flow:
//  1. Client sends Noise IK msg1 in the request body
//  2. Server reads msg1, verifies authentication
//  3. If auth fails → return fallback-like response (constant-time path)
//  4. If auth succeeds → respond with Noise IK msg2, then bidirectional
//     DATA frames carry tunnel traffic
//
// AuthFunc is called with the request body (Noise msg1). It returns:
//   - resp: the Noise msg2 response bytes (nil on auth failure)
//   - conn: a bidirectional stream for tunnel data (nil on auth failure)
//   - err: non-nil on auth failure
type AuthFunc func(msg1 []byte) (resp []byte, conn io.ReadWriteCloser, err error)

// TunnelHandler returns an http.Handler that performs the Noise IK handshake
// and, on success, bridges the HTTP/2 stream to the tunnel. On auth failure,
// the request is forwarded to the fallback handler (constant-time: same code
// path, same response timing).
//
// The handshake uses length-prefixed framing (L3 envelope):
//
//	Client → Server: [uint16BE len][msg1 bytes]  ... then raw tunnel data
//	Server → Client: [uint16BE len][msg2 bytes]  ... then raw tunnel data
//
// onAuth is called with the raw Noise msg1. If it returns an error, the
// fallback handler is invoked instead — the active prober sees the same
// response it would get for any random POST to the fallback site.
func TunnelHandler(onAuth AuthFunc, fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Read length-prefixed Noise IK msg1 from request body.
		msg1, err := readLengthPrefixed(r.Body)
		if err != nil || len(msg1) == 0 {
			fallback.ServeHTTP(w, r)
			return
		}

		resp, tunnel, authErr := onAuth(msg1)
		if authErr != nil {
			// Auth failed — fall through to the real website.
			fallback.ServeHTTP(w, r)
			return
		}

		// Auth succeeded — send length-prefixed Noise msg2, then
		// stream tunnel data.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)

		// Write length-prefixed msg2 response.
		if err := writeLengthPrefixed(w, resp); err != nil {
			if tunnel != nil {
				tunnel.Close()
			}
			return
		}

		// Flush to ensure msg2 reaches the client before we start
		// streaming tunnel data.
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		// Bridge: bidirectional copy between HTTP/2 stream and tunnel.
		if tunnel != nil {
			bridge(r.Body, w, tunnel)
		}
	})
}

// readLengthPrefixed reads a [uint16BE length][payload] message.
// Max payload size is 64KB. Returns the payload bytes.
func readLengthPrefixed(r io.Reader) ([]byte, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("read length prefix: %w", err)
	}
	n := binary.BigEndian.Uint16(lenBuf[:])
	if n == 0 {
		return nil, fmt.Errorf("zero-length message")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read message body: %w", err)
	}
	return buf, nil
}

// writeLengthPrefixed writes a [uint16BE length][payload] message.
func writeLengthPrefixed(w io.Writer, data []byte) error {
	if len(data) > 65535 {
		return fmt.Errorf("message too large: %d", len(data))
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(data)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(data)
	return err
}

// bridge copies data bidirectionally between the HTTP/2 stream (request body
// for client→server, response writer for server→client) and the tunnel.
func bridge(reqBody io.Reader, respWriter io.Writer, tunnel io.ReadWriteCloser) {
	defer tunnel.Close()

	done := make(chan struct{}, 2)

	// tunnel → client (via HTTP/2 response body)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := tunnel.Read(buf)
			if n > 0 {
				if _, werr := respWriter.Write(buf[:n]); werr != nil {
					return
				}
				if f, ok := respWriter.(http.Flusher); ok {
					f.Flush()
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// client → tunnel (via HTTP/2 request body)
	go func() {
		defer func() { done <- struct{}{} }()
		_, _ = io.Copy(tunnel, reqBody)
	}()

	// Wait for either direction to finish.
	<-done
}
