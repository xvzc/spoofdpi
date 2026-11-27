package desync

import (
	"context"
	"net"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/logging"
)

type UDPDesyncer struct {
	logger zerolog.Logger
	writer Writer
	hops   HopReader
	caps   FakeCapability
}

// NewUDPDesyncer returns a desyncer that sends fake packets with writer,
// to the destinations caps allows; a nil caps allows every destination.
func NewUDPDesyncer(
	logger zerolog.Logger,
	writer Writer,
	hops HopReader,
	caps FakeCapability,
) *UDPDesyncer {
	return &UDPDesyncer{logger: logger, writer: writer, hops: hops, caps: caps}
}

// PrepareHopTrack registers addrs for UDP hop-count learning, guarded by
// the config so the LRU isn't touched when fakes won't be sent.
func (d *UDPDesyncer) PrepareHopTrack(addrs []net.IP, cfg *config.UDPOptions) {
	if d.hops == nil || cfg.FakePreflight == 0 {
		return
	}
	d.hops.Register(ProtoUDP, addrs)
}

// Desync sends fake packets on the flow of rConn, the connection to the
// server.
func (d *UDPDesyncer) Desync(
	ctx context.Context,
	rConn net.Conn,
	opts *config.UDPOptions,
	connOpts *config.ConnOptions,
) (int, error) {
	logger := logging.WithLocalScope(ctx, d.logger, "udp_desync")

	if opts.FakePreflight == 0 || d.hops == nil || d.writer == nil {
		return 0, nil
	}

	dstIP := rConn.RemoteAddr().(*net.UDPAddr).IP
	if linkScoped(dstIP) {
		logLinkScoped(logger, dstIP)
		return 0, nil
	}
	if err := checkFake(d.caps, dstIP); err != nil {
		logCannotFake(logger, dstIP, err)
		return 0, nil
	}
	est := d.hops.Lookup(ProtoUDP, dstIP)
	if onLocalLink(est) {
		if d.hops.MarkWarned(ProtoUDP, dstIP) {
			warnLocalLink(logger, dstIP)
		} else {
			logger.Trace().Msg("server is on the local link, skipping fake packets")
		}
		return 0, nil
	}
	policy := hopPolicy(connOpts)
	oTTL := policy.TTL(est)

	var totalSent int
	for range opts.FakePreflight {
		n, err := d.writer.WriteCraftedPacket(
			ctx,
			// Same 5-tuple as the real flow, so DPI tracks the fakes with it.
			rConn.LocalAddr(),
			rConn.RemoteAddr(),
			oTTL,
			opts.FakePacket,
		)
		if err != nil {
			logger.Warn().Err(err).Msg("failed to send fake packet")
			continue
		}
		totalSent += n
	}

	if totalSent > 0 {
		logger.Debug().
			Uint8("count", opts.FakePreflight).
			Int("bytes", totalSent).
			Stringer("hop_source", est.Source).
			Uint8("hops", policy.Hops(est)).
			Uint8("ttl", oTTL).
			Msg("sent fake packets")
	}

	return totalSent, nil
}
