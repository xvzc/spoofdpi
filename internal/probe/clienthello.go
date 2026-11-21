package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/xvzc/spoofdpi/internal/proto"
)

// benignSNI is the server name of the residual block check: one the DPI
// is not expected to block.
const benignSNI = "example.com"

// errFirstFlight stops the TLS handshake once the ClientHello is written.
var errFirstFlight = errors.New("first flight captured")

// helloRecorder is a net.Conn that records what the TLS client writes and
// fails every call, so that the handshake stops after the ClientHello.
type helloRecorder struct {
	buf bytes.Buffer
}

func (c *helloRecorder) Write(b []byte) (int, error) {
	c.buf.Write(b)
	return 0, errFirstFlight
}

func (c *helloRecorder) Read([]byte) (int, error)         { return 0, errFirstFlight }
func (c *helloRecorder) Close() error                     { return nil }
func (c *helloRecorder) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *helloRecorder) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *helloRecorder) SetDeadline(time.Time) error      { return nil }
func (c *helloRecorder) SetReadDeadline(time.Time) error  { return nil }
func (c *helloRecorder) SetWriteDeadline(time.Time) error { return nil }

// buildClientHello returns the ClientHello Go's TLS client sends to host,
// with fresh random values and key shares. An IP literal host gets no SNI,
// as in browsers. The key exchanges are pinned, so that the size does not
// change with the Go version.
func buildClientHello(host string) (*proto.TLSMessage, error) {
	rec := &helloRecorder{}
	conn := tls.Client(rec, &tls.Config{
		ServerName: host,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{
			tls.X25519MLKEM768, tls.X25519, tls.CurveP256,
		},
	})
	err := conn.HandshakeContext(context.Background())
	if !errors.Is(err, errFirstFlight) {
		return nil, fmt.Errorf("build ClientHello: %w", err)
	}
	msg, err := proto.ReadTLSMessage(bytes.NewReader(rec.buf.Bytes()))
	if err != nil {
		return nil, fmt.Errorf("build ClientHello: %w", err)
	}
	if !msg.IsClientHello() {
		return nil, errors.New("build ClientHello: not a ClientHello")
	}
	return msg, nil
}

// sessionIDOffset is the offset of the session ID length in a record
// holding a ClientHello or a ServerHello: record header 5, handshake
// header 4, version 2 and random 32.
const sessionIDOffset = 43

// sessionID returns the session ID of the ClientHello record raw, or nil
// if raw is too short.
func sessionID(raw []byte) []byte {
	if len(raw) <= sessionIDOffset {
		return nil
	}
	end := sessionIDOffset + 1 + int(raw[sessionIDOffset])
	if len(raw) < end {
		return nil
	}
	return raw[sessionIDOffset+1 : end]
}
