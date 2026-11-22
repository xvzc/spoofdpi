package proto

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// SOCKS5 Protocol Constants
const (
	// Version
	SOCKSVersion = 0x05

	// Auth
	SOCKS5AuthNone     = 0x00
	SOCKS5AuthGSSAPI   = 0x01
	SOCKS5AuthUserPass = 0x02
	SOCKS5AuthNoAccept = 0xFF

	// Command
	SOCKS5CmdConnect      = 0x01
	SOCKS5CmdBind         = 0x02
	SOCKS5CmdUDPAssociate = 0x03

	// ATYP
	SOCKS5AddrTypeIPv4 = 0x01
	SOCKS5AddrTypeFQDN = 0x03
	SOCKS5AddrTypeIPv6 = 0x04

	// Reply codes
	SOCKS5RCodeSuccess          = 0x00
	SOCKS5RCodeGenFailure       = 0x01
	SOCKS5RCodeCmdNotSupported  = 0x07
	SOCKS5RCodeAddrNotSupported = 0x08
)

type SOCKS5Request struct {
	Cmd  byte
	ATYP byte
	FQDN string
	IP   net.IP
	Port int
}

// ReadSocks5Request parses the SOCKS5 request details.
func ReadSocks5Request(conn net.Conn) (*SOCKS5Request, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	if header[0] != SOCKSVersion {
		return nil, fmt.Errorf(
			"version mismatch: expected %x, got %x",
			SOCKSVersion,
			header[0],
		)
	}

	cmd := header[1]
	atyp := header[3]

	var domain string
	var ip net.IP

	switch atyp {
	case SOCKS5AddrTypeIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}

		ip = net.IP(buf)

	case SOCKS5AddrTypeFQDN:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}

		domainLen := int(lenBuf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return nil, err
		}
		domain = string(domainBuf)

	case SOCKS5AddrTypeIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		ip = net.IP(buf)

	default:
		return nil, fmt.Errorf("unsupported atyp: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}
	port := int(binary.BigEndian.Uint16(portBuf))

	return &SOCKS5Request{
		Cmd:  cmd,
		ATYP: atyp,
		FQDN: domain,
		IP:   ip,
		Port: port,
	}, nil
}

type SOCKS5Reply struct {
	Rep      byte
	BindIP   net.IP
	BindPort int
}

func NewSOCKS5Reply(rep byte) *SOCKS5Reply {
	return &SOCKS5Reply{
		Rep:      rep,
		BindIP:   net.IPv4zero,
		BindPort: 0,
	}
}

func SOCKS5SuccessResponse() *SOCKS5Reply {
	return NewSOCKS5Reply(SOCKS5RCodeSuccess)
}

func SOCKS5FailureResponse() *SOCKS5Reply {
	return NewSOCKS5Reply(SOCKS5RCodeGenFailure)
}

func SOCKS5CommandNotSupportedResponse() *SOCKS5Reply {
	return NewSOCKS5Reply(SOCKS5RCodeCmdNotSupported)
}

func (r *SOCKS5Reply) Bind(ip net.IP) *SOCKS5Reply {
	if ip != nil {
		r.BindIP = ip
	}
	return r
}

func (r *SOCKS5Reply) Port(port int) *SOCKS5Reply {
	r.BindPort = port
	return r
}

// Write writes r. BindIP is sent as an IPv4 address (ATYP 1) when it is
// IPv4 or IPv4-mapped, as an IPv6 address (ATYP 4) otherwise, and as
// 0.0.0.0 when it is nil.
func (r *SOCKS5Reply) Write(w io.Writer) error {
	atyp, addr := byte(SOCKS5AddrTypeIPv4), net.IPv4zero.To4()
	if ip4 := r.BindIP.To4(); ip4 != nil {
		addr = ip4
	} else if ip6 := r.BindIP.To16(); ip6 != nil {
		atyp, addr = SOCKS5AddrTypeIPv6, ip6
	}

	buf := make([]byte, 0, 4+len(addr)+2)
	buf = append(buf, SOCKSVersion, r.Rep, 0x00, atyp)
	buf = append(buf, addr...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(r.BindPort))

	_, err := w.Write(buf)
	return err
}
