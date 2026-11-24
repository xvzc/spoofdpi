package server

import (
	"net"
	"net/netip"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/netutil"
	"github.com/xvzc/spoofdpi/internal/proto"
)

// tlsAlertWarnedCapacity bounds the destinations a TLSAlertWatcher
// remembers having warned about.
const tlsAlertWarnedCapacity = 4096

const tlsAlertMsg = "the server answered the Client Hello with a TLS alert"

// TLSAlertWatcher logs a TLS alert that a server answers the Client Hello
// with. A fake Client Hello that reaches the server makes it answer so. It
// warns once per destination IP, and logs at debug level after that. All
// handlers share one, so that the state is process-wide.
type TLSAlertWatcher struct {
	warned cache.Cache[netutil.IPKey, struct{}]
}

func NewTLSAlertWatcher() *TLSAlertWatcher {
	return &TLSAlertWatcher{
		warned: cache.NewLRUCache[netutil.IPKey, struct{}](
			16, tlsAlertWarnedCapacity, nil,
		),
	}
}

// Inspector returns a function that checks the first bytes read from rConn
// for a TLS alert, for netutil.TunnelConnsFirstRead. It only logs. sni is
// the server name of the Client Hello, and host the name the client asked
// for; either may be empty. It returns nil when rConn has no TCP address,
// which makes the tunnel copy without inspecting.
//
// A TLS alert is 7 bytes that a server sends at once, so a first read that
// returns fewer is not checked: buffering until there are 7 would hold
// bytes back from the client.
func (w *TLSAlertWatcher) Inspector(
	logger zerolog.Logger,
	rConn net.Conn,
	sni string,
	host string,
) func(first []byte) {
	dst, ok := rConn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil
	}

	return func(first []byte) {
		if alert, ok := proto.ParseTLSAlert(first); ok {
			w.report(logger, alert, dst, sni, host)
		}
	}
}

// report logs alert, which the server at dst answered the Client Hello with.
func (w *TLSAlertWatcher) report(
	logger zerolog.Logger,
	alert proto.TLSAlertMessage,
	dst *net.TCPAddr,
	sni string,
	host string,
) {
	// A host that is an IP literal is not a name to probe.
	if _, err := netip.ParseAddr(host); err == nil {
		host = ""
	}

	// Set reports whether the IP was not there yet, atomically.
	first := w.warned.Set(
		netutil.NewIPKey(dst.IP),
		struct{}{},
		cache.Options().WithSkipExisting(true),
	)

	event := logger.Debug()
	if first {
		event = logger.Warn()
	}
	event = event.Str("alert", alert.Name()).Str("dst", dst.String())
	name := sni
	if sni != "" {
		event = event.Str("sni", sni)
	} else if host != "" {
		event = event.Str("host", host)
		name = host
	}

	if !first || !alert.RejectsClientHello() {
		event.Msg(tlsAlertMsg)
		return
	}

	// The console format puts the fields after the message, so the hint
	// can't follow them as one sentence; it is part of the message.
	hint := tlsAlertMsg + "; if fake packets are on, they may have reached " +
		"the server: try a lower connection.hop-count-offset (default -1)"
	if name != "" {
		hint += ", or check with 'spoofdpi probe " + name + "'"
	}
	event.Msg(hint)
}

// SNI returns the server name of msg, or an empty string when it has none.
func SNI(msg *proto.TLSMessage) string {
	start, end, err := msg.ExtractSNIOffset()
	if err != nil {
		return ""
	}
	return string(msg.Raw()[start:end])
}
