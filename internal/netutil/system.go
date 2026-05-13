package netutil

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
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

func RunPACServer(content string) (string, *http.Server, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(content))
	})

	server := &http.Server{
		Handler: mux,
	}

	go func() {
		_ = server.Serve(listener)
	}()

	addr := listener.Addr().(*net.TCPAddr)
	url := fmt.Sprintf("http://127.0.0.1:%d/proxy.pac", addr.Port)

	return url, server, nil
}
