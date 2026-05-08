package packet

import (
	"net"

	"github.com/xvzc/spoofdpi/internal/cache"
	"github.com/xvzc/spoofdpi/internal/netutil"
)

type Sniffer interface {
	StartCapturing()
	Track(addrs []net.IP)
	GetOptimalTTL(key netutil.IPKey) uint8
	Cache() cache.Cache[netutil.IPKey, uint8]
}

// estimateHops estimates the number of hops based on TTL.
// This logic is based on the hop counting mechanism from GoodbyeDPI.
// It returns 0 if the TTL is not recognizable.
func estimateHops(ttlLeft uint8) uint8 {
	// Unrecognizable initial TTL
	estimatedInitialHops := uint8(255)
	switch {
	case ttlLeft <= 64:
		estimatedInitialHops = 64
	case ttlLeft <= 128:
		estimatedInitialHops = 128
	default:
		estimatedInitialHops = 255
	}

	return estimatedInitialHops - ttlLeft
}

// isLocalIP checks if an IP address is in a local/private range.
// This is used to filter out outgoing packets from local machine.
// Private ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8
func isLocalIP(ip []byte) bool {
	if len(ip) < 4 {
		return false
	}

	// 10.0.0.0/8
	if ip[0] == 10 {
		return true
	}

	// 127.0.0.0/8 (loopback)
	if ip[0] == 127 {
		return true
	}

	// 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
	if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
		return true
	}

	// 192.168.0.0/16
	if ip[0] == 192 && ip[1] == 168 {
		return true
	}

	// 169.254.0.0/16 (link-local)
	if ip[0] == 169 && ip[1] == 254 {
		return true
	}

	return false
}
