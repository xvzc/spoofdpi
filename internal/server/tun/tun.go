package tun

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/logging"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/route"
	"github.com/xvzc/spoofdpi/internal/server"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Ensure tcpip is used to avoid "imported and not used" error
var _ tcpip.NetworkProtocolNumber = ipv4.ProtocolNumber

// TUNSystemNetwork handles OS-specific network configuration for TUN mode.
type TUNSystemNetwork interface {
	TunDevice() tun.Device
	FIBID() int
	BindDialer(dialer *net.Dialer, network string, targetIP net.IP) error
	BuildJobs() ([]server.NetworkJob, error)
}

// gatewayIP returns the next hop of rt as the TUN job builders print it,
// or "" when rt has no gateway, as on a point-to-point uplink such as
// PPP.
func gatewayIP(rt *route.Route) string {
	if rt.Gateway == nil {
		return ""
	}
	return rt.Gateway.String()
}

// ipv6CaptureCIDR is the IPv6 range routed into the TUN when IPv6 is enabled
// and the host has an IPv6 route to the internet. It covers global unicast addresses only, so
// link-local, unique local and multicast traffic keeps its on-link routes.
const ipv6CaptureCIDR = "2000::/3"

// ipv6RejectWarning is logged once the IPv6 capture route has been added.
const ipv6RejectWarning = "IPv6 traffic is routed into the TUN and refused so " +
	"applications fall back to IPv4; IPv6-only destinations are unreachable " +
	"in TUN mode"

// ipv6Policy decides what the TUN server does with connections to IPv6
// destinations.
type ipv6Policy int

const (
	// ipv6PolicyReject refuses them: TCP gets a RST and UDP an ICMPv6 port
	// unreachable, so dual-stack clients fall back to IPv4, which goes
	// through the desync path.
	ipv6PolicyReject ipv6Policy = iota
)

type TunServer struct {
	logger zerolog.Logger

	v6Policy ipv6Policy

	tcpHandler *TCPHandler
	udpHandler *UDPHandler

	sysNet TUNSystemNetwork

	device   tun.Device
	netStack *stack.Stack
	ep       *channel.Endpoint
	conns    server.ConnTracker

	// serveCtx is the context Serve runs with. Serve sets it before it starts
	// the packet pump, and the forwarders only see connections once packets
	// flow, so the forwarder callbacks always read it after it is set.
	serveCtx context.Context
}

func NewTUNServer(
	logger zerolog.Logger,
	tcpHandler *TCPHandler,
	udpHandler *UDPHandler,
	sysNet TUNSystemNetwork,
) server.Server {
	return &TunServer{
		logger:     logger,
		v6Policy:   ipv6PolicyReject,
		tcpHandler: tcpHandler,
		udpHandler: udpHandler,
		sysNet:     sysNet,
	}
}

func (s *TunServer) Listen(ctx context.Context) error {
	logger := logging.WithLocalScope(ctx, s.logger, "tun")

	tunDevice := s.sysNet.TunDevice()
	if tunDevice == nil {
		return fmt.Errorf("tun device not available")
	}

	// 1. Create gVisor stack
	stk := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
		},
	})

	// 2. Create channel endpoint
	ep := channel.New(256, 1500, "")

	const nicID = 1
	if err := stk.CreateNIC(nicID, ep); err != nil {
		return fmt.Errorf("failed to create NIC: %v", err)
	}
	stk.EnableNIC(nicID)

	// 3. Enable Promiscuous mode & Spoofing
	stk.SetPromiscuousMode(nicID, true)
	stk.SetSpoofing(nicID, true)
	stk.SetForwardingDefaultAndAllNICs(ipv4.ProtocolNumber, true)
	stk.SetForwardingDefaultAndAllNICs(ipv6.ProtocolNumber, true)

	// 3.5. Add default route to the stack
	// Define a subnet that matches all IPv4 addresses (0.0.0.0/0)
	defaultSubnet4, _ := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		tcpip.MaskFrom("\x00\x00\x00\x00"),
	)

	defaultSubnet6, _ := tcpip.NewSubnet(
		tcpip.AddrFrom16([16]byte{}),
		tcpip.MaskFrom(strings.Repeat("\x00", 16)),
	)

	stk.SetRouteTable([]tcpip.Route{
		{Destination: defaultSubnet4, NIC: nicID},
		{Destination: defaultSubnet6, NIC: nicID},
	})

	// 4. Register TCP Forwarder
	tcpFwd := tcp.NewForwarder(stk, 0, 65535, func(r *tcp.ForwarderRequest) {
		if s.refuses(r.ID()) {
			logger.Debug().
				Str("dst", r.ID().LocalAddress.String()).
				Msg("refusing tcp connection to ipv6 destination")
			r.Complete(true)
			return
		}

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			logger.Error().
				Str("type", fmt.Sprintf("%T", err)).
				Str("local", r.ID().LocalAddress.String()).
				Str("remote", r.ID().RemoteAddress.String()).
				Msgf("failed to create tcp endpoint: %v", err)

			r.Complete(true)
			return
		}
		r.Complete(false)

		conn := gonet.NewTCPConn(&wq, ep)

		dst, dstErr := connToDst(conn)
		if dstErr != nil {
			logger.Error().Err(dstErr).Msg("failed to resolve tcp destination")
			_ = conn.Close()
			return
		}
		s.conns.Go(s.serveCtx, conn, func(ctx context.Context) {
			s.tcpHandler.Handle(ctx, conn, dst, s.sysNet)
		})
	})
	stk.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	// 5. Register UDP Forwarder
	udpFwd := udp.NewForwarder(stk, func(r *udp.ForwarderRequest) bool {
		if s.refuses(r.ID()) {
			logger.Debug().
				Str("dst", r.ID().LocalAddress.String()).
				Msg("refusing udp flow to ipv6 destination")
			// An unhandled datagram makes the stack answer with an ICMP port
			// unreachable.
			return false
		}

		var wq waiter.Queue
		ep, err := r.CreateEndpoint(&wq)
		if err != nil {
			logger.Error().Str("type", fmt.Sprintf("%T", err)).
				Msgf("failed to create udp endpoint: %v", err)

			return true
		}

		conn := gonet.NewUDPConn(&wq, ep)

		dst, dstErr := connToDst(conn)
		if dstErr != nil {
			logger.Error().Err(dstErr).Msg("failed to resolve udp destination")
			_ = conn.Close()
			return true
		}
		s.conns.Go(s.serveCtx, conn, func(ctx context.Context) {
			s.udpHandler.Handle(ctx, conn, dst, s.sysNet)
		})
		return true
	})
	stk.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	s.device = tunDevice
	s.netStack = stk
	s.ep = ep

	return nil
}

// Serve pumps packets between the TUN device and the network stack until ctx
// is cancelled. It then closes the TUN device, waits for open connections to
// end, and destroys the network stack, waiting at most
// server.ShutdownSafetyTimeout for each of the last two steps.
func (s *TunServer) Serve(ctx context.Context) error {
	logger := logging.WithLocalScope(ctx, s.logger, "tun")
	s.serveCtx = ctx

	// 6. Start packet pump
	go func() {
		go s.tunToStack(ctx, logger, s.ep, s.device)
		s.stackToTun(ctx, logger, s.ep, s.device)
	}()

	<-ctx.Done()
	_ = s.device.Close()

	if !s.conns.Wait(server.ShutdownSafetyTimeout) {
		s.logger.Warn().
			Int64("count", s.conns.Active()).
			Msg("connections still open at shutdown")
	}

	// The connections' gonet conns belong to the stack, so it goes last.
	destroyed := make(chan struct{})
	go func() {
		s.netStack.Destroy()
		close(destroyed)
	}()
	select {
	case <-destroyed:
	case <-time.After(server.ShutdownSafetyTimeout):
		s.logger.Warn().Msg("network stack still stopping at shutdown")
	}

	return nil
}

// refuses reports whether the server refuses the connection id, whose local
// address is the original packet destination.
func (s *TunServer) refuses(id stack.TransportEndpointID) bool {
	return id.LocalAddress.Len() == header.IPv6AddressSize &&
		s.v6Policy == ipv6PolicyReject
}

// networkProtocol returns the network protocol of the IP packet from its
// version nibble, and false for a version the stack does not handle.
func networkProtocol(packet []byte) (tcpip.NetworkProtocolNumber, bool) {
	switch packet[0] >> 4 {
	case 4:
		return ipv4.ProtocolNumber, true
	case 6:
		return ipv6.ProtocolNumber, true
	default:
		return 0, false
	}
}

// connToDst builds a Destination from the connection's local address.
// In TUN mode, LocalAddr is always the original packet destination IP.
func connToDst(conn net.Conn) (*netutil.Destination, error) {
	host, portStr, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return nil, fmt.Errorf("invalid local addr %q: %w", conn.LocalAddr(), err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("non-ip destination %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf(
			"non-numeric port %q in local addr %q",
			portStr,
			conn.LocalAddr(),
		)
	}
	return &netutil.Destination{
		Host:  host,
		Port:  port,
		Addrs: []net.IP{ip},
	}, nil
}

func (s *TunServer) Addr() string {
	if dev := s.sysNet.TunDevice(); dev != nil {
		if name, err := dev.Name(); err == nil {
			return name
		}
	}
	return "tun"
}

func (s *TunServer) ActiveConns() int64 {
	return s.conns.Active()
}

func (s *TunServer) tunToStack(
	appctx context.Context,
	logger zerolog.Logger,
	ep *channel.Endpoint,
	tunDevice tun.Device,
) {
	const (
		// readOffset is the headroom before each IP packet in the read buffer.
		// wireguard-go on Linux (IFF_VNET_HDR) writes the virtio-net header into
		// buf[offset-virtioNetHdrLen:offset], so offset must be >= 10.
		// On macOS the value just acts as padding; >= 4 is sufficient.
		// We use 10 so a single constant works on all platforms.
		readOffset = 10
		mtu        = 1500
	)

	// Batch size: on Linux with IFF_VNET_HDR, BatchSize() returns
	// conn.IdealBatchSize (typically 128). handleVirtioRead → gsoSplit writes
	// each GRO sub-segment into a separate bufs[i] slot. If len(bufs) < number
	// of segments, gsoSplit returns ErrTooManySegments. We must therefore
	// pre-allocate exactly BatchSize() buffers.
	batchSize := tunDevice.BatchSize()

	// Allocate all per-packet buffers from a single contiguous backing array to
	// keep allocations low.
	const bufSize = readOffset + mtu
	backing := make([]byte, batchSize*bufSize)
	bufs := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range bufs {
		bufs[i] = backing[i*bufSize : (i+1)*bufSize]
	}

	for {
		// Reset sizes before each Read; wireguard-go overwrites them with actual
		// packet lengths.
		for i := range sizes {
			sizes[i] = mtu
		}

		n, err := tunDevice.Read(bufs, sizes, readOffset)
		if err != nil {
			if errors.Is(err, fs.ErrClosed) || errors.Is(err, os.ErrClosed) {
				return
			}
			select {
			case <-appctx.Done():
				return
			default:
				if err != io.EOF {
					logger.Error().Err(err).Msg("failed to read from tun")
				}
				return
			}
		}

		// Process each packet returned by this Read call (n >= 1 on success).
		for i := range n {
			if sizes[i] < 1 {
				continue
			}

			packet := bufs[i][readOffset : readOffset+sizes[i]]

			proto, ok := networkProtocol(packet)
			if !ok {
				logger.Trace().Int("version", int(packet[0]>>4)).Msg("skipping non-ip packet")
				continue
			}

			payload := buffer.MakeWithData(append([]byte(nil), packet...))
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: payload})
			ep.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}
}

type notifier struct {
	ch chan<- struct{}
}

func (n *notifier) WriteNotify() {
	select {
	case n.ch <- struct{}{}:
	default:
	}
}

func (s *TunServer) stackToTun(
	appctx context.Context,
	logger zerolog.Logger,
	ep *channel.Endpoint,
	tunDevice tun.Device,
) {
	ch := make(chan struct{}, 1)
	n := &notifier{ch: ch}
	ep.AddNotify(n)

	// Pool of []byte slices to avoid per-packet allocation.
	// Each buffer holds a headroom prefix followed by the IP packet.
	//
	// The offset must be >= 10 (virtioNetHdrLen) on Linux because wireguard-go
	// enables IFF_VNET_HDR, and its Write() implementation does:
	//   offset -= virtioNetHdrLen  (i.e. offset -= 10)
	// to place the virtio-net header in buf[offset-10:offset] before writing.
	// With offset=4 this would compute a negative index, silently dropping every
	// packet written back to the TUN device (no response ever reaches the client).
	// On macOS the TUN device only needs offset >= 4 (AF-family header), so 10 is
	// safe on all platforms.
	const writeOffset = 10
	pool := &sync.Pool{
		New: func() any {
			b := make([]byte, writeOffset+1500)
			return &b
		},
	}

	for {
		select {
		case <-appctx.Done():
			return
		default:
		}

		pkt := ep.Read()
		if pkt == nil {
			select {
			case <-ch:
				continue
			case <-appctx.Done():
				return
			}
		}

		views := pkt.ToView().AsSlice()
		if len(views) > 0 {
			// wireguard-go Write(bufs, offset) writes the 4-byte AF family header into
			// buf[offset-4:offset] and reads the IP packet from buf[offset:].
			// We must therefore prepend 4 zero bytes so the IP payload starts at index 4.
			needed := writeOffset + len(views)
			bp := pool.Get().(*[]byte)
			if cap(*bp) < needed {
				*bp = make([]byte, needed)
			}
			buf := (*bp)[:needed]
			copy(buf[writeOffset:], views)
			_, _ = tunDevice.Write([][]byte{buf}, writeOffset)
			pool.Put(bp)
		}
		pkt.DecRef()
	}
}

func (s *TunServer) SetupNetworkJobs(_ context.Context) (string, error) {
	jobs, err := s.sysNet.BuildJobs()
	if err != nil {
		return "", err
	}
	return StateFile, server.SaveJobs(StateFile, jobs)
}
