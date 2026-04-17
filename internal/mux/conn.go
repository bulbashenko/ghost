package mux

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"
)

// PingInterval is the default time between keepalive pings.
const PingInterval = 30 * time.Second

// PingTimeout is how long to wait for a ping response.
const PingTimeout = 10 * time.Second

// Conn is a multiplexed connection over a single bidirectional byte stream.
// It manages logical streams, dispatches incoming frames, and handles
// connection-level control frames (PING, PADDING).
type Conn struct {
	enc *Encoder
	dec *Decoder

	// isClient determines stream ID parity: client uses odd IDs, server even.
	isClient bool
	nextID   uint32

	streams  map[uint32]*Stream
	streamMu sync.Mutex

	// onStream is called when the peer opens a new stream. If nil, new
	// streams from the peer are rejected.
	onStream func(*Stream)

	done     chan struct{}
	closeErr error
	closeOnce sync.Once
}

// NewConn creates a multiplexed connection over the given transport.
//   - rw: the bidirectional stream (e.g. the HTTP/2 DATA channel)
//   - isClient: true for the client side (odd stream IDs), false for server (even)
//   - onStream: called when the peer opens a new stream (may be nil)
func NewConn(rw io.ReadWriter, isClient bool, onStream func(*Stream)) *Conn {
	c := &Conn{
		enc:      NewEncoder(rw),
		dec:      NewDecoder(rw),
		isClient: isClient,
		streams:  make(map[uint32]*Stream),
		onStream: onStream,
		done:     make(chan struct{}),
	}
	if isClient {
		c.nextID = 1 // odd
	} else {
		c.nextID = 2 // even
	}
	go c.readLoop()
	return c
}

// OpenStream creates a new logical stream and sends STREAM_OPEN to the peer.
func (c *Conn) OpenStream() (*Stream, error) {
	c.streamMu.Lock()
	id := c.nextID
	c.nextID += 2 // maintain odd/even parity
	s := newStream(id, c)
	c.streams[id] = s
	c.streamMu.Unlock()

	err := c.enc.WriteFrame(&Frame{
		Version:  ProtocolVersion,
		Type:     TypeStreamOpen,
		StreamID: id,
	})
	if err != nil {
		c.streamMu.Lock()
		delete(c.streams, id)
		c.streamMu.Unlock()
		return nil, fmt.Errorf("mux: open stream: %w", err)
	}
	return s, nil
}

// SendPing sends a PING frame with a random 8-byte cookie.
func (c *Conn) SendPing() error {
	cookie := make([]byte, 8)
	if _, err := rand.Read(cookie); err != nil {
		return err
	}
	return c.enc.WriteFrame(&Frame{
		Version:  ProtocolVersion,
		Type:     TypePing,
		StreamID: 0,
		Payload:  cookie,
	})
}

// SendPadding sends a PADDING frame with n random bytes (L5 traffic shaping).
func (c *Conn) SendPadding(n int) error {
	if n <= 0 || n > MaxPayload {
		return fmt.Errorf("mux: padding size %d out of range", n)
	}
	payload := make([]byte, n)
	if _, err := rand.Read(payload); err != nil {
		return err
	}
	return c.enc.WriteFrame(&Frame{
		Version:  ProtocolVersion,
		Type:     TypePadding,
		StreamID: 0,
		Payload:  payload,
	})
}

// Close terminates the connection and all streams.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		c.streamMu.Lock()
		for _, s := range c.streams {
			s.deliverErr(io.EOF)
		}
		c.streamMu.Unlock()
	})
	return nil
}

// Done returns a channel that's closed when the connection terminates.
func (c *Conn) Done() <-chan struct{} {
	return c.done
}

// readLoop reads frames from the wire and dispatches them.
func (c *Conn) readLoop() {
	defer c.Close()

	for {
		f, err := c.dec.ReadFrame()
		if err != nil {
			c.closeErr = err
			return
		}
		c.dispatch(f)
	}
}

func (c *Conn) dispatch(f *Frame) {
	switch f.Type {
	case TypeData:
		c.streamMu.Lock()
		s := c.streams[f.StreamID]
		c.streamMu.Unlock()
		if s != nil {
			s.deliverData(f.Payload)
		}

	case TypeStreamOpen:
		c.streamMu.Lock()
		s := newStream(f.StreamID, c)
		c.streams[f.StreamID] = s
		c.streamMu.Unlock()
		if c.onStream != nil {
			go c.onStream(s)
		}

	case TypeStreamClose:
		c.streamMu.Lock()
		s := c.streams[f.StreamID]
		delete(c.streams, f.StreamID)
		c.streamMu.Unlock()
		if s != nil {
			s.deliverErr(io.EOF)
		}

	case TypePing:
		// Echo the ping cookie back.
		_ = c.enc.WriteFrame(&Frame{
			Version:  ProtocolVersion,
			Type:     TypePing,
			StreamID: 0,
			Payload:  f.Payload,
		})

	case TypePadding:
		// Discard — this is L5 traffic shaping padding.

	case TypeWindowUpdate:
		// Flow control — acknowledged but not enforced in v1.
		// Full implementation deferred to when needed.

	default:
		// Unknown frame types are silently ignored for forward compatibility.
	}
}
