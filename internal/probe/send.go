package probe

import (
	"context"
	"errors"
	"net"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/desync"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
)

// helloSender sends a ClientHello the way spoofdpi does, split as the
// options say.
type helloSender interface {
	Desync(
		ctx context.Context,
		conn net.Conn,
		msg *proto.TLSMessage,
		opts *config.HTTPSOptions,
		connOpts *config.ConnOptions,
	) (int, error)
}

// newHelloSender returns spoofdpi's own desyncer, without fake packets.
func newHelloSender() helloSender {
	return desync.NewTLSDesyncer(zerolog.Nop(), nil, nil, nil, nil)
}

// unsplitOpts sends the ClientHello in one write.
func unsplitOpts() *config.HTTPSOptions {
	return &config.HTTPSOptions{SplitMode: config.HTTPSSplitModeNone}
}

// chunkOpts sends the ClientHello in writes of size bytes, as spoofdpi's
// split-mode chunk does.
func chunkOpts(size int) *config.HTTPSOptions {
	return &config.HTTPSOptions{
		SplitMode: config.HTTPSSplitModeChunk,
		ChunkSize: uint8(size),
	}
}

// disorderOpts is chunkOpts with disorder: every other chunk, from the
// first, leaves with TTL 1 and reaches the server only when retransmitted.
func disorderOpts(size int) *config.HTTPSOptions {
	o := chunkOpts(size)
	o.Disorder = true
	return o
}

// errCannotSetTTL is returned when the TTL of a connection cannot be set.
var errCannotSetTTL = errors.New("cannot set TTL")

// sendHello sends msg on conn with opts. For disorder, it first checks
// that conn's TTL can be set: the desyncer ignores a failure to set it and
// sends the chunks in order instead.
func sendHello(
	ctx context.Context,
	s helloSender,
	conn net.Conn,
	msg *proto.TLSMessage,
	opts *config.HTTPSOptions,
) error {
	if opts.Disorder {
		// 64 is the TTL the desyncer restores after each disordered chunk.
		if err := netutil.SetTTL(conn, true, 64); err != nil {
			return errCannotSetTTL
		}
	}
	// No fake packets are sent, so no hop-count options are needed.
	_, err := s.Desync(ctx, conn, msg, opts, &config.ConnOptions{})
	return err
}
