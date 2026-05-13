package packet

import "net"

// Route represents the default network route with gateway information.
type Route struct {
	Iface      net.Interface
	Gateway    net.IP
	GatewayMAC net.HardwareAddr
}
