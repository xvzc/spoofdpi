package config

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/xvzc/spoofdpi/internal/proto"
)

// ┌─────────────────┐
// │ APP OPTIONS     │
// └─────────────────┘

var availableLogLevelValues = []string{
	"info",
	"warn",
	"trace",
	"error",
	"debug",
	"disabled",
}

type AppOptions struct {
	NoTUI                bool          `toml:"no-tui"`
	LogLevel             zerolog.Level `toml:"log-level"`
	Silent               bool          `toml:"silent"`
	AutoConfigureNetwork bool          `toml:"auto-configure-network"`
	Mode                 AppModeType   `toml:"mode"`
	ListenAddr           net.TCPAddr   `toml:"listen-addr"`
	Gateway              Gateways      `toml:"gateway"`     // zero: discover from the routing table
	FreebsdFIB           int           `toml:"freebsd-fib"` // FreeBSD only: FIB ID for routing (2-15)
	// IPv6 is the global ipv6 option. Rules inherit it unless they set
	// their own; RuntimeConfig.IPv6 holds the value a connection uses.
	IPv6 bool `toml:"ipv6"`
}

func (o *AppOptions) UnmarshalTOML(data any) (err error) {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("non-table type general config")
	}

	if p := findFrom(m, "no-tui", parseBoolFn(), &err); isOk(p, err) {
		o.NoTUI = *p
	}
	if p := findFrom(m, "silent", parseBoolFn(), &err); isOk(p, err) {
		o.Silent = *p
	}
	if p := findFrom(m, "auto-configure-network", parseBoolFn(), &err); isOk(p, err) {
		o.AutoConfigureNetwork = *p
	}
	if p := findFrom(m, "log-level", parseStringFn(checkLogLevel), &err); isOk(p, err) {
		o.LogLevel = MustParseLogLevel(*p)
	}
	if p := findFrom(m, "mode", parseStringFn(checkAppMode), &err); isOk(p, err) {
		o.Mode = MustParseServerModeType(*p)
	}
	if p := findFrom(m, "listen-addr", parseStringFn(checkHostPort), &err); isOk(p, err) {
		o.ListenAddr = MustParseTCPAddr(*p)
	}
	if p := findFrom(m, "gateway", parseGatewaysFn(), &err); isOk(p, err) {
		o.Gateway = *p
	}
	if p := findFrom(
		m,
		"freebsd-fib",
		parseIntFn[int](checkFreeBSDFibID),
		&err,
	); isOk(
		p,
		err,
	) {
		o.FreebsdFIB = *p
	}
	if p := findFrom(m, "ipv6", parseBoolFn(), &err); isOk(p, err) {
		o.IPv6 = *p
	}

	return err
}

// TODO(l3): since fake packets are sent at L3, gateway only overrides the
// interface of packet capture and of TUN mode's route out of the TUN.
// Reconsider whether it is still needed, or deprecate it.
//
// Gateways is the gateway option: at most one gateway per address family.
// A nil address is discovered from the routing table.
type Gateways struct {
	V4 net.IP
	V6 net.IP
	// V6Zone is the zone of V6, which only a link-local V6 may have.
	V6Zone string
}

// IsZero reports whether no gateway is set.
func (g Gateways) IsZero() bool {
	return g.V4 == nil && g.V6 == nil
}

// String returns the gateways that are set, separated by ", ", such as
// "192.168.1.1, fe80::1%en0".
func (g Gateways) String() string {
	var parts []string
	if g.V4 != nil {
		parts = append(parts, g.V4.String())
	}
	if g.V6 != nil {
		v6 := g.V6.String()
		if g.V6Zone != "" {
			v6 += "%" + g.V6Zone
		}
		parts = append(parts, v6)
	}
	return strings.Join(parts, ", ")
}

// ┌──────────────┐
// │ APP MODE     │
// └──────────────┘

type AppModeType int

const (
	AppModeHTTP AppModeType = iota
	AppModeSOCKS5
	AppModeTUN
)

var availableAppModeValues = []string{"http", "socks5", "tun"}

func (t AppModeType) String() string {
	return availableAppModeValues[t]
}

func (t AppModeType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

// ┌────────────────────┐
// │ CONNECTION OPTIONS │
// └────────────────────┘

type ConnOptions struct {
	// Hop count to the server, which sets the TTL of fake packets.
	// HopCountDefault is assumed until the hop count is learned. The hop
	// count, learned or default, is clamped to [HopCountMin, HopCountMax],
	// and HopCountOffset is then added to it to give the TTL.
	HopCountDefault uint8         `toml:"hop-count-default"`
	HopCountMin     uint8         `toml:"hop-count-min"`
	HopCountMax     uint8         `toml:"hop-count-max"`
	HopCountOffset  int8          `toml:"hop-count-offset"`
	TCPTimeout      time.Duration `toml:"tcp-timeout"`
	UDPIdleTimeout  time.Duration `toml:"udp-idle-timeout"`
}

// MarshalJSON renders durations via String() (e.g. "10s") instead of
// raw nanoseconds so trace logs are readable.
func (o ConnOptions) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		HopCountDefault uint8  `json:"hop-count-default"`
		HopCountMin     uint8  `json:"hop-count-min"`
		HopCountMax     uint8  `json:"hop-count-max"`
		HopCountOffset  int8   `json:"hop-count-offset"`
		TCPTimeout      string `json:"tcp-timeout"`
		UDPIdleTimeout  string `json:"udp-idle-timeout"`
	}{
		HopCountDefault: o.HopCountDefault,
		HopCountMin:     o.HopCountMin,
		HopCountMax:     o.HopCountMax,
		HopCountOffset:  o.HopCountOffset,
		TCPTimeout:      o.TCPTimeout.String(),
		UDPIdleTimeout:  o.UDPIdleTimeout.String(),
	})
}

func (o *ConnOptions) UnmarshalTOML(data any) (err error) {
	v, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("non-table type connection config")
	}

	// default-fake-ttl is the deprecated name of hop-count-default. When
	// both are present, the deprecated one is ignored.
	//
	// TODO(deprecated): renamed to hop-count-default after v1.6.0. Remove
	// with the --default-fake-ttl flag (cli.go) and the note in
	// docs/user-guide/connection.md.
	if p := findFrom(
		v,
		renamedKey(v, "hop-count-default", "default-fake-ttl"),
		parseIntFn[uint8](checkUint8NonZero),
		&err,
	); isOk(
		p,
		err,
	) {
		o.HopCountDefault = *p
	}
	if p := findFrom(
		v,
		"hop-count-min",
		parseIntFn[uint8](checkUint8),
		&err,
	); isOk(
		p,
		err,
	) {
		o.HopCountMin = *p
	}
	if p := findFrom(
		v,
		"hop-count-max",
		parseIntFn[uint8](checkUint8NonZero),
		&err,
	); isOk(p, err) {
		o.HopCountMax = *p
	}
	if p := findFrom(
		v,
		"hop-count-offset",
		parseIntFn[int8](checkInt8),
		&err,
	); isOk(
		p,
		err,
	) {
		o.HopCountOffset = *p
	}
	if p := findFrom(
		v,
		"tcp-timeout",
		parseIntFn[uint32](checkConnTimeout),
		&err,
	); isOk(
		p,
		err,
	) {
		o.TCPTimeout = time.Duration(*p) * time.Millisecond
	}
	if p := findFrom(
		v,
		"udp-idle-timeout",
		parseIntFn[uint32](checkConnTimeout),
		&err,
	); isOk(
		p,
		err,
	) {
		o.UDPIdleTimeout = time.Duration(*p) * time.Millisecond
	}

	return err
}

// ┌─────────────┐
// │ DNS OPTIONS │
// └─────────────┘

type (
	DNSModeType  int
	DNSQueryType int
)

var (
	availableDNSModeValues = []string{"udp", "https", "system"}
	// availableDNSQueryValues names the DNSQueryType values in logs. They are
	// no longer option values: the query type follows the ipv6 option.
	// DNSQueryIPv6 (AAAA only) is not derived yet; it is kept for the record
	// types chosen by the host's IPv6 egress (see dnsQueryType).
	availableDNSQueryValues = []string{"ipv4", "ipv6", "all"}
)

const (
	DNSModeUDP DNSModeType = iota
	DNSModeHTTPS
	DNSModeSystem
)

const (
	DNSQueryIPv4 DNSQueryType = iota
	DNSQueryIPv6
	DNSQueryAll
)

func (t DNSModeType) String() string {
	return availableDNSModeValues[t]
}

func (t DNSModeType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

func (t DNSQueryType) String() string {
	return availableDNSQueryValues[t]
}

func (t DNSQueryType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

type DNSOptions struct {
	Mode     DNSModeType `toml:"mode"`
	Addr     net.TCPAddr `toml:"addr"`
	HTTPSURL string      `toml:"https-url"`
	// QType is the record types to query. It is not an option: it is
	// derived from the ipv6 option of the same RuntimeConfig (see
	// dnsQueryType), and it is part of the DNS cache key.
	QType DNSQueryType `toml:"-"`
	// Timeout bounds each DNS lookup; it must be at least 1ms.
	Timeout time.Duration `toml:"timeout"`
}

// dnsQueryType returns the record types to query for a connection whose
// ipv6 option is ipv6.
//
// TODO(ipv6): with ipv6 on, pick the record types by the host's IPv6
// egress ("auto", Phase 5 of the IPv6 plan) instead of always both.
func dnsQueryType(ipv6 bool) DNSQueryType {
	if ipv6 {
		return DNSQueryAll
	}
	return DNSQueryIPv4
}

// MarshalJSON renders Addr as "host:port" (net.TCPAddr's default
// JSON dumps each field separately), Timeout via String() (e.g. "5s")
// and lets the enums use their MarshalText for string output. QType is
// left out: it follows the ipv6 option, which RuntimeConfig shows.
func (o DNSOptions) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Mode     DNSModeType `json:"mode"`
		Addr     string      `json:"addr"`
		HTTPSURL string      `json:"https-url"`
		Timeout  string      `json:"timeout"`
	}{
		Mode:     o.Mode,
		Addr:     o.Addr.String(),
		HTTPSURL: o.HTTPSURL,
		Timeout:  o.Timeout.String(),
	})
}

func (o *DNSOptions) UnmarshalTOML(data any) (err error) {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("'dns' must be table type")
	}

	if p := findFrom(m, "mode", parseStringFn(checkDNSMode), &err); isOk(p, err) {
		o.Mode = MustParseDNSModeType(*p)
	}
	if p := findFrom(m, "addr", parseStringFn(checkHostPort), &err); isOk(p, err) {
		o.Addr = MustParseTCPAddr(*p)
	}
	if p := findFrom(
		m,
		"https-url",
		parseStringFn(checkHTTPSEndpoint),
		&err,
	); isOk(
		p,
		err,
	) {
		o.HTTPSURL = *p
	}
	// TODO(deprecated): the record types follow the ipv6 option since
	// 'qtype' was removed after v1.6.0. Remove this warning with
	// --dns-qtype (cli.go).
	if _, ok := m["qtype"]; ok {
		AddWarnMsg(
			"'dns.qtype' is deprecated and ignored; " +
				"set 'ipv6 = true' in [app], or in the rule, to resolve IPv6 addresses",
		)
	}
	// TODO(deprecated): DNS answers are always cached since the 'cache'
	// option was removed after v1.6.0. Remove this warning with
	// --dns-cache (cli.go).
	if _, ok := m["cache"]; ok {
		AddWarnMsg("'dns.cache' is deprecated and ignored; DNS answers are always cached")
	}
	if p := findFrom(
		m,
		"timeout",
		parseIntFn[uint16](checkDNSTimeout),
		&err,
	); isOk(
		p,
		err,
	) {
		o.Timeout = time.Duration(*p) * time.Millisecond
	}

	return
}

// ┌───────────────┐
// │ HTTPS OPTIONS │
// └───────────────┘

const FakeClientHello = "" +
	"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\x9a\x8f\xa7" +
	"\x6a\x5d\x57\xf3\x62\x19\xbe\x46\x82\x45\xe2\x59\x5c\xb4" +
	"\x48\x31\x12\x15\x14\x79\x2c\xaa\xcd\xea\xda\xf0\xe1\xfd" +
	"\xbb\x20\xf4\x83\x2a\x94\xf1\x48\x3b\x9d\xb6\x74\xba\x3c" +
	"\x81\x63\xbc\x18\xcc\x14\x45\x57\x6c\x80\xf9\x25\xcf\x9c" +
	"\x86\x60\x50\x31\x2e\xe9\x00\x22\x13\x01\x13\x03\x13\x02" +
	"\xc0\x2b\xc0\x2f\xcc\xa9\xcc\xa8\xc0\x2c\xc0\x30\xc0\x0a" +
	"\xc0\x09\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35" +
	"\x01\x00\x01\x91\x00\x00\x00\x14\x00\x12\x00\x00\x0f\x77" +
	"\x77\x77\x2e\x67\x6f\x6f\x67\x6c\x65\x2e\x63\x6f\x6d\x00" +
	"\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0e\x00\x0c" +
	"\x00\x1d\x00\x17\x00\x18\x00\x19\x01\x00\x01\x01\x00\x0b" +
	"\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10\x00\x0e\x00\x0c" +
	"\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x05" +
	"\x00\x05\x01\x00\x00\x00\x00\x00\x0d\x00\x18\x00\x16\x04" +
	"\x03\x05\x03\x06\x03\x08\x04\x08\x05\x08\x06\x04\x01\x05" +
	"\x01\x06\x01\x02\x03\x02\x01\x00\x12\x00\x00\x00\x33\x00" +
	"\x6b\x00\x69\x00\x1d\x00\x20\x67\xb1\x88\x18\x47\x6e\xc3" +
	"\xc1\x83\x73\xb1\xa9\x80\x42\x36\xb6\xe1\x66\x6e\xb6\x6c" +
	"\x32\x9b\xc3\xf3\x18\x29\x7c\xff\xc1\x77\x7c\x00\x17\x00" +
	"\x41\x04\xa6\xb6\xb1\xb1\xc6\x4d\xb1\x86\xa1\x8a\x80\x4d" +
	"\xa6\x35\x57\xa1\xc4\x88\x9a\x9c\xa9\x6d\x6e\x67\xa6\x47" +
	"\x59\xc6\x82\x10\x06\xc9\x9b\x12\x91\x6c\xa1\xc4\x8d\xb1" +
	"\xc6\x95\xa9\xc7\x9c\x06\xa1\xa3\x83\xb6\x59\xa6\x40\x73" +
	"\x83\xc6\x95\x59\xa9\xb1\x18\xc1\x6d\x9b\xa6\x49\x9c\x47" +
	"\x16\xc1\xa6\x59\xa9\x18\xc7\x9c\x18\x4d\xa6\x9b\x4d\x6d" +
	"\x57\x16\x16\x95\xa6\xc7\x96\x67\x96\x16\x69\x82\x95\x91" +
	"\x83\x49\xc7\x06\x82\x6c\xb6\x6c\x96\xa3\xc1\xb1\xc1\x86" +
	"\x16\xa3\xc1\xb1\xc4\x95\xa6\x67\xb1\x86\xa3\xc1\xa6\x16" +
	"\xa6\xc4\x06\x6e\x6d\x99\x47\x6c\xa1\x82\x06\xc4\x18\xa6" +
	"\xc4\x69\xa3\x9b\xa3\x40\x6e\xa9\xb1\xa6\x95\x73\xc1\x88" +
	"\x06\x95\x4d\xa9\x40\x4d\x67\x88\x96\xa6\x67\x18\x06\x69" +
	"\x99\xa3\x88\x88\xa9\x6e\xa1\x99\x06\x95\x06\xa9\x83\x4d" +
	"\x16\x73\x47\x88\x67\xa6\x6c\xa6\x18\xc1\xa6\x95\x59\xa3" +
	"\x9b\x96\xa3\x73\xb6\x06\xa1\x18\x6e\x67\x67\xa1\x91\x4d" +
	"\xa6\x59\x9c\x82\x86\x95\x16\xa3\x47\x95\x18\x96\x95\x06" +
	"\xa6\xc7\x47\xc7\x82\x47\x9b\x18\x73\x9b\x18\x91\x99\x18" +
	"\x9c\xa6\x9c\xa9\x67\xc7\x96\x18\x06\xc4\x9c\xc4\x83\x47" +
	"\x18\x59\x96\x47\x91\xa1\x47\x06\xb6\x69\x6c\x99\x4d\x69" +
	"\xa1\x59\x18\xc1\x47\x6c\x6e\x91\x9b\x6e\x67\xa6\x91\xa3" +
	"\xc4\x47\xb1\x47\xa3\x95\x49\x73\x95\x88\x18\x59\x82\xc7" +
	"\xa9\x99\xc6\x99\xa3\x88\x6c\x67\x6c\xa6\xa6\xb1\xc7\x67" +
	"\x59\x99\x06\x4d\xa3\x95\x49\xc4\x69\x6e\x4d\x96\x47\x4d" +
	"\xa1\xa1\xa1\x99\xa9\xb1\x82\xa9\x16\x40\x95\x95\x82\x82" +
	"\x91\x47\xa6\x40\x91\x91\x99\xa9\x06\xa9\x88\x9c\xa9\xa9" +
	"\x18\x47\x6e\x9b\x9b\xa3\xa9\xc7\x6e\xa3\xa3\xc7\xb1\x47" +
	"\x4d\x83\xa9\xc4\x49\x4d\x9c\x91\xa9\x47\xb6\xa9\x4d\x47"

type HTTPSSplitModeType int

var availableHTTPSModeValues = []string{
	"sni",
	"random",
	"chunk",
	"first-byte",
	"custom",
	"none",
}

const (
	HTTPSSplitModeSNI HTTPSSplitModeType = iota
	HTTPSSplitModeRandom
	HTTPSSplitModeChunk
	HTTPSSplitModeFirstByte
	HTTPSSplitModeCustom
	HTTPSSplitModeNone
)

func (k HTTPSSplitModeType) String() string {
	return availableHTTPSModeValues[k]
}

func (k HTTPSSplitModeType) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

type SegmentFromType int

var availableSegmentFromValues = []string{"head", "sni"}

const (
	SegmentFromHead SegmentFromType = iota
	SegmentFromSNI
)

func (s SegmentFromType) String() string {
	return availableSegmentFromValues[s]
}

func (s SegmentFromType) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

type SegmentPlan struct {
	From  SegmentFromType `toml:"from"`
	At    int             `toml:"at"`
	Lazy  bool            `toml:"lazy"`
	Noise int             `toml:"noise"`
}

func (s *SegmentPlan) UnmarshalTOML(data any) (err error) {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("segment must be table type")
	}

	if _, ok := m["from"]; !ok {
		return fmt.Errorf("field 'from' is required")
	}
	if p := findFrom(m, "from", parseStringFn(checkSegmentFrom), &err); isOk(p, err) {
		s.From = mustParseSegmentFromType(*p)
	}

	if _, ok := m["at"]; !ok {
		return fmt.Errorf("field 'at' is required")
	}
	if p := findFrom(m, "at", parseIntFn[int](nil), &err); isOk(p, err) {
		s.At = *p
	}

	if p := findFrom(m, "lazy", parseBoolFn(), &err); isOk(p, err) {
		s.Lazy = *p
	}

	if p := findFrom(m, "noise", parseIntFn[int](nil), &err); isOk(p, err) {
		s.Noise = *p
	}

	return err
}

// renamedKey returns the key to read for an option whose old name was
// old: key, unless only the old name is set. Using the old name warns;
// with both set, the old one is ignored with a warning.
func renamedKey(m map[string]any, key, old string) string {
	if _, ok := m[old]; !ok {
		return key
	}
	if _, both := m[key]; both {
		AddWarnMsg(fmt.Sprintf("'%s' is ignored because '%s' is set", old, key))
		return key
	}
	AddWarnMsg(fmt.Sprintf("'%s' is deprecated; rename to '%s'", old, key))
	return old
}

type HTTPSOptions struct {
	Disorder      bool               `toml:"disorder"`
	FakePreflight uint8              `toml:"fake-preflight"`
	FakeStutter   uint8              `toml:"fake-stutter"`
	FakePacket    *proto.TLSMessage  `toml:"fake-packet"`
	FakeSeqOffset int64              `toml:"fake-seq-offset"`
	FakeAckOffset int64              `toml:"fake-ack-offset"`
	FakeBadMD5Sig bool               `toml:"fake-bad-md5sig"`
	SynAckTimeout time.Duration      `toml:"syn-ack-timeout"`
	SplitMode     HTTPSSplitModeType `toml:"split-mode"`
	ChunkSize     uint8              `toml:"-"`
	Skip          bool               `toml:"skip"`
	CustomSplit   []SegmentPlan      `toml:"custom-split"`
}

// UsesFakes reports whether fake packets are sent: before the Client
// Hello (FakePreflight) or before each of its segments (FakeStutter).
func (o HTTPSOptions) UsesFakes() bool {
	return o.FakePreflight > 0 || o.FakeStutter > 0
}

// MarshalJSON omits FakePacket (a 64-byte buffer that's noise in trace
// logs), surfaces fake-packet length separately, and renders
// CustomSplit as a compact "N items" count for the same reason
// MatchAttrs does — segment plans are static config the user defined,
// not something to re-dump on every match trace.
func (o HTTPSOptions) MarshalJSON() ([]byte, error) {
	out := struct {
		Disorder      bool               `json:"disorder"`
		FakePreflight uint8              `json:"fake-preflight"`
		FakeStutter   uint8              `json:"fake-stutter"`
		FakePacketLen int                `json:"fake-packet-len,omitempty"`
		FakeSeqOffset int64              `json:"fake-seq-offset"`
		FakeAckOffset int64              `json:"fake-ack-offset"`
		FakeBadMD5Sig bool               `json:"fake-bad-md5sig"`
		SynAckTimeout string             `json:"syn-ack-timeout"`
		SplitMode     HTTPSSplitModeType `json:"split-mode"`
		ChunkSize     uint8              `json:"chunk-size"`
		Skip          bool               `json:"skip"`
		CustomSplit   string             `json:"custom-split,omitempty"`
	}{
		Disorder:      o.Disorder,
		FakePreflight: o.FakePreflight,
		FakeStutter:   o.FakeStutter,
		FakePacketLen: fakePacketLen(o.FakePacket),
		FakeSeqOffset: o.FakeSeqOffset,
		FakeAckOffset: o.FakeAckOffset,
		FakeBadMD5Sig: o.FakeBadMD5Sig,
		SynAckTimeout: o.SynAckTimeout.String(),
		SplitMode:     o.SplitMode,
		ChunkSize:     o.ChunkSize,
		Skip:          o.Skip,
	}
	if n := len(o.CustomSplit); n > 0 {
		out.CustomSplit = fmt.Sprintf("%d items", n)
	}
	return json.Marshal(out)
}

func fakePacketLen(m *proto.TLSMessage) int {
	if m == nil {
		return 0
	}
	return len(m.Raw())
}

func (o *HTTPSOptions) UnmarshalTOML(data any) (err error) {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("'tls' must be table type")
	}

	if p := findFrom(m, "disorder", parseBoolFn(), &err); isOk(p, err) {
		o.Disorder = *p
	}
	// TODO(deprecated): fake-count was renamed to fake-preflight after
	// v1.6.0; remove the fallback with --tls-fake-count and
	// --https-fake-count (cli.go) and the note in docs/user-guide/tls.md.
	if p := findFrom(
		m,
		renamedKey(m, "fake-preflight", "fake-count"),
		parseIntFn[uint8](checkUint8),
		&err,
	); isOk(p, err) {
		o.FakePreflight = *p
	}

	if p := findFrom(
		m,
		"fake-stutter",
		parseIntFn[uint8](checkUint8),
		&err,
	); isOk(
		p,
		err,
	) {
		o.FakeStutter = *p
	}

	if fakePacket := findSliceFrom(
		m,
		"fake-packet",
		parseByteFn(nil),
		&err,
	); fakePacket != nil {
		o.FakePacket = proto.NewFakeTLSMessage(fakePacket)
	}

	if p := findFrom(
		m,
		"fake-seq-offset",
		parseIntFn[int64](checkSeqOffset),
		&err,
	); isOk(
		p,
		err,
	) {
		o.FakeSeqOffset = *p
	}
	if p := findFrom(
		m,
		"fake-ack-offset",
		parseIntFn[int64](checkSeqOffset),
		&err,
	); isOk(
		p,
		err,
	) {
		o.FakeAckOffset = *p
	}
	if p := findFrom(m, "fake-bad-md5sig", parseBoolFn(), &err); isOk(p, err) {
		o.FakeBadMD5Sig = *p
	}
	if p := findFrom(
		m,
		"syn-ack-timeout",
		parseIntFn[uint16](checkUint16),
		&err,
	); isOk(p, err) {
		o.SynAckTimeout = time.Duration(*p) * time.Millisecond
	}

	// TODO(deprecated): chunk-size was folded into split-mode ("chunk:N")
	// after v1.6.0 and is only warned about; remove the warning with
	// --https-chunk-size (cli.go) and the note in docs/user-guide/tls.md.
	if _, ok := m["chunk-size"]; ok {
		AddWarnMsg(
			"'chunk-size' is no longer supported and is ignored; " +
				"use 'split-mode = \"chunk:N\"'",
		)
	}
	if p := findFrom(
		m,
		"split-mode",
		parseStringFn(checkHTTPSSplitMode),
		&err,
	); isOk(
		p,
		err,
	) {
		mode, size := mustParseSplitMode(*p)
		o.SplitMode = mode
		if size > 0 {
			o.ChunkSize = size
		}
	}
	if p := findFrom(m, "skip", parseBoolFn(), &err); isOk(p, err) {
		o.Skip = *p
	}

	// TODO(deprecated): custom-segments was renamed to custom-split after
	// v1.6.0; remove the fallback and the note in docs/user-guide/tls.md.
	if plans := findStructSliceFrom[SegmentPlan](
		m,
		renamedKey(m, "custom-split", "custom-segments"),
		&err,
	); plans != nil {
		o.CustomSplit = plans
	}
	if err == nil && o.SplitMode == HTTPSSplitModeCustom &&
		len(o.CustomSplit) == 0 {
		err = fmt.Errorf("custom-split must be provided when split-mode is 'custom'")
	}

	return err
}

// ┌─────────────┐
// │ UDP OPTIONS │
// └─────────────┘

type UDPOptions struct {
	Skip          bool   `toml:"skip"`
	FakePreflight uint8  `toml:"fake-preflight"`
	FakePacket    []byte `toml:"fake-packet"`
}

// MarshalJSON omits the raw FakePacket bytes (default is 64 zeros,
// dumped as base64 they're trace-log noise) but surfaces the length
// so the user can tell whether a packet is configured.
func (o UDPOptions) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Skip          bool  `json:"skip"`
		FakePreflight uint8 `json:"fake-preflight"`
		FakePacketLen int   `json:"fake-packet-len,omitempty"`
	}{
		Skip:          o.Skip,
		FakePreflight: o.FakePreflight,
		FakePacketLen: len(o.FakePacket),
	})
}

func (o *UDPOptions) UnmarshalTOML(data any) (err error) {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("'udp' must be table type")
	}

	if p := findFrom(m, "skip", parseBoolFn(), &err); isOk(p, err) {
		o.Skip = *p
	}
	// TODO(deprecated): fake-count was renamed to fake-preflight after
	// v1.6.0; remove the fallback with --udp-fake-count (cli.go) and the
	// note in docs/user-guide/udp.md.
	if p := findFrom(
		m,
		renamedKey(m, "fake-preflight", "fake-count"),
		parseIntFn[uint8](checkUint8),
		&err,
	); isOk(p, err) {
		o.FakePreflight = *p
	}
	if fp := findSliceFrom(m, "fake-packet", parseByteFn(nil), &err); fp != nil {
		o.FakePacket = fp
	}

	return err
}

// ┌──────────────┐
// │ ADDR MATCH   │
// └──────────────┘

// ┌──────────────┐
// │ MATCH ATTRS  │
// └──────────────┘

type MatchAttrs struct {
	Domains []string `toml:"domains"`
	CIDRs   []string `toml:"cidrs"`
}

func (a MatchAttrs) MarshalJSON() ([]byte, error) {
	out := struct {
		Domains string `json:"domains,omitempty"`
		CIDRs   string `json:"cidrs,omitempty"`
	}{}
	if n := len(a.Domains); n > 0 {
		out.Domains = fmt.Sprintf("%d items", n)
	}
	if n := len(a.CIDRs); n > 0 {
		out.CIDRs = fmt.Sprintf("%d items", n)
	}
	return json.Marshal(out)
}

func (a *MatchAttrs) UnmarshalTOML(data any) (err error) {
	v, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("'match' must be table type")
	}

	if raw := findSliceFrom(v, "domains", parseStringFn(nil), &err); raw != nil {
		for _, d := range raw {
			if e := checkDomainPattern(d); e != nil {
				return fmt.Errorf("invalid domain %q: %w", d, e)
			}
		}
		a.Domains = raw
	}

	if raw := findSliceFrom(v, "cidrs", parseStringFn(nil), &err); raw != nil {
		for _, c := range raw {
			if e := checkCIDR(c); e != nil {
				return fmt.Errorf("invalid cidr %q: %w", c, e)
			}
		}
		a.CIDRs = raw
	}

	if err == nil {
		err = checkMatchAttrs(*a)
	}

	return err
}

// ┌──────┐
// │ RULE │
// └──────┘

type Rule struct {
	Name     string      `toml:"name"     json:"name"`
	Priority uint16      `toml:"priority" json:"priority"`
	Block    bool        `toml:"block"    json:"block"`
	Match    *MatchAttrs `toml:"match"    json:"match,omitempty"`
	// IPv6 is the rule's own ipv6, nil when the rule does not set it.
	// Config.IPv6 holds the value the rule applies, inherited when nil.
	IPv6   *bool         `toml:"ipv6" json:"ipv6,omitempty"`
	Config RuntimeConfig `toml:"-"    json:"config"`
}

// IPv4Only reports whether r keeps its connections to IPv4 addresses: it
// sets ipv6 = false itself. A nil rule, and a rule that inherits ipv6, do
// not, so they still connect to IPv6 literals.
func (r *Rule) IPv4Only() bool {
	return r != nil && r.IPv6 != nil && !*r.IPv6
}

// UnmarshalTOML decodes the standalone fields of a Rule. The per-section
// config overrides (dns/tls/udp/connection) are NOT decoded here —
// resolveRules in load.go handles them so it can pre-fill from the
// finalized base RuntimeConfig before overlaying the rule's TOML.
func (r *Rule) UnmarshalTOML(data any) (err error) {
	m, ok := data.(map[string]any)
	if !ok {
		return fmt.Errorf("'rule' must be table type")
	}

	if p := findFrom(m, "name", parseStringFn(nil), &err); isOk(p, err) {
		r.Name = *p
	}
	if p := findFrom(m, "priority", parseIntFn[uint16](checkUint16), &err); isOk(p, err) {
		r.Priority = *p
	}
	if p := findFrom(m, "block", parseBoolFn(), &err); isOk(p, err) {
		r.Block = *p
	}
	// Only the rule's own setting: Config.IPv6, like the other config
	// sections, is resolved by resolveRules.
	if p := findFrom(m, "ipv6", parseBoolFn(), &err); isOk(p, err) {
		r.IPv6 = p
	}
	r.Match = findStructFrom[MatchAttrs](m, "match", &err)

	return
}

// Clone returns a shallow copy of r. Matchers use this so callers receive
// a rule they can't accidentally mutate back into the matcher's state.
func (r *Rule) Clone() *Rule {
	if r == nil {
		return nil
	}
	c := *r
	return &c
}

// JSON returns the rule serialized for trace logging. Per-section
// MarshalJSON handles enum-as-string, addr-as-"host:port",
// duration-as-string, IPNet-as-CIDR, and elides large fake-packet
// buffers in favor of a length, so the output is compact and
// human-readable on a single line.
func (r *Rule) JSON() []byte {
	b, _ := json.Marshal(r)
	return b
}

// MustParseLogLevel keeps the legacy string-to-zerolog conversion exported
// for callers that previously normalised log levels via this helper.
var _ = strings.ToLower
