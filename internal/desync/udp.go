package desync

import (
	"context"
	"net"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/config"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/packet"
)

type UDPDesyncer struct {
	logger  zerolog.Logger
	writer  packet.Writer
	sniffer packet.Sniffer
}

func NewUDPDesyncer(logger zerolog.Logger, writer packet.Writer, sniffer packet.Sniffer) *UDPDesyncer {
	return &UDPDesyncer{logger: logger, writer: writer, sniffer: sniffer}
}

// PrepareHopTrack registers addrs with the sniffer for hop-count learning,
// guarded by the config so the LRU isn't touched when fakes won't be sent.
func (d *UDPDesyncer) PrepareHopTrack(addrs []net.IP, cfg *config.UDPOptions) {
	if d.sniffer != nil && cfg != nil && cfg.FakeCount > 0 {
		d.sniffer.Register(addrs)
	}
}

func (d *UDPDesyncer) Desync(
	ctx context.Context,
	lConn net.Conn,
	rConn net.Conn,
	opts *config.UDPOptions,
) (int, error) {
	logger := logging.WithLocalScope(ctx, d.logger, "udp_desync")

	if d.sniffer == nil || d.writer == nil || opts == nil || opts.FakeCount <= 0 {
		return 0, nil
	}

	dstIP := rConn.RemoteAddr().(*net.UDPAddr).IP
	oTTL := d.sniffer.GetOptimalTTL(netutil.NewIPKey(dstIP))

	var totalSent int
	for range opts.FakeCount {
		n, err := d.writer.WriteCraftedPacket(
			ctx,
			lConn.LocalAddr(), // Spoofing source: original local address (TUN)
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
			Int("count", opts.FakeCount).
			Int("bytes", totalSent).
			Uint8("ttl", oTTL).
			Msg("sent fake packets")
	}

	return totalSent, nil
}
