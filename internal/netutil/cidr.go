package netutil

import (
	"encoding/binary"
	"fmt"
	"net"
)

func FindSafeCIDR() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	var existingNets []*net.IPNet
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			existingNets = append(existingNets, ipnet)
		}
	}

	for i := 0; i < 256; i++ {
		for j := 0; j < 256; j++ {
			local := net.IPv4(10, byte(i), byte(j), 1)
			remote := net.IPv4(10, byte(i), byte(j), 2)

			conflict := false
			for _, ipnet := range existingNets {
				if ipnet.Contains(local) || ipnet.Contains(remote) {
					conflict = true
					break
				}
			}

			if !conflict {
				return fmt.Sprintf("10.%d.%d.0/30", i, j), nil
			}
		}
	}

	return "", fmt.Errorf("failed to find an available address in 10.0.0.0/8")
}

func AddrInCIDR(cidr string, n int) (string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", err
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return "", fmt.Errorf("not an IPv4 CIDR")
	}

	ipInt := binary.BigEndian.Uint32(ip4)

	resultInt := ipInt + uint32(n)

	resultIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(resultIP, resultInt)

	if !ipnet.Contains(resultIP) {
		return "", fmt.Errorf("index %d is out of CIDR range %s", n, cidr)
	}

	return resultIP.String(), nil
}
