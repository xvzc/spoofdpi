//go:build darwin || freebsd

package inject

import "golang.org/x/net/ipv4"

// What differs on darwin and FreeBSD:
//
//   - ipv4.Header.Marshal writes ip_len and ip_off in host order on
//     darwin and on FreeBSD before 11, and in network order from FreeBSD
//     11 on, as each kernel expects with IP_HDRINCL.
//   - The IPv4 socket's route is the kernel's for the header's
//     destination, or, in TUN mode, the one that Options.Control pins it
//     to (IP_BOUND_IF on darwin, SO_SETFIB on FreeBSD). The packets need
//     no ancillary data for it.

// ipv4Control returns the ancillary data that p is sent with: none.
func ipv4Control(Packet) *ipv4.ControlMessage { return nil }
