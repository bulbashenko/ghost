package tun

import (
	"encoding/hex"
	"io"
	"log/slog"

	"github.com/bulbashenko/ghost/internal/mux"
)

// Bridge copies packets bidirectionally between a TUN device and a mux stream.
//
//	TUN → Stream: IP packets read from TUN are written as DATA frames
//	Stream → TUN: DATA frames received from peer are written as IP packets
//
// Bridge blocks until either direction encounters an error or the stream/device
// is closed. It returns the first error that caused shutdown.
func Bridge(dev *Device, stream *mux.Stream) error {
	errc := make(chan error, 2)

	// TUN → mux stream
	go func() {
		buf := make([]byte, dev.MTU()+100)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				errc <- err
				return
			}
			if n == 0 {
				continue
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				errc <- err
				return
			}
		}
	}()

	// mux stream → TUN
	go func() {
		buf := make([]byte, dev.MTU()+100)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				if err == io.EOF {
					errc <- nil
				} else {
					errc <- err
				}
				return
			}
			if n == 0 {
				continue
			}

			pkt := buf[:n]

			// Validate IP packet before writing to TUN.
			// The kernel rejects anything that isn't a valid IP packet
			// with EINVAL. Log and skip rather than crashing the bridge.
			if !isValidIPPacket(pkt) {
				hdr := pkt
				if len(hdr) > 32 {
					hdr = hdr[:32]
				}
				slog.Warn("bridge: dropping non-IP packet",
					"len", n,
					"hex", hex.EncodeToString(hdr),
				)
				continue
			}

			if _, err := dev.Write(pkt); err != nil {
				// Log the packet header for diagnostics.
				hdr := pkt
				if len(hdr) > 32 {
					hdr = hdr[:32]
				}
				slog.Error("tun write failed",
					"error", err,
					"pkt_len", n,
					"hex", hex.EncodeToString(hdr),
				)
				errc <- err
				return
			}
		}
	}()

	err := <-errc
	if err != nil {
		slog.Debug("tun bridge stopped", "error", err)
	}
	return err
}

// isValidIPPacket checks the minimum requirements for writing to a TUN device:
//   - At least 20 bytes (minimum IPv4 header)
//   - IP version nibble is 4 (IPv4) or 6 (IPv6)
//   - For IPv4: total length in header matches packet length (±tolerance)
func isValidIPPacket(pkt []byte) bool {
	if len(pkt) < 1 {
		return false
	}

	version := pkt[0] >> 4

	switch version {
	case 4:
		// IPv4: minimum header is 20 bytes.
		if len(pkt) < 20 {
			return false
		}
		// Check that IP total length is consistent with buffer.
		totalLen := int(pkt[2])<<8 | int(pkt[3])
		if totalLen < 20 || totalLen > len(pkt) {
			return false
		}
		return true

	case 6:
		// IPv6: minimum header is 40 bytes.
		if len(pkt) < 40 {
			return false
		}
		return true

	default:
		return false
	}
}
