//go:build !linux

package probe

import "github.com/google/gopacket/pcap"

// errReadTimeout is the error a capture handle's read returns when its
// read timeout expires.
var errReadTimeout error = pcap.NextErrorTimeoutExpired
