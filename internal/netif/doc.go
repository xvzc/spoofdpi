// Package netif configures network interfaces with the kernel's interface
// ioctls on darwin and FreeBSD: IPv4 addresses, interface flags, and, on
// FreeBSD, destroying a cloned interface and asking whether a process holds a
// tun open. It replaces the ifconfig commands of TUN mode.
//
// Errors wrap the kernel's errno, so callers test them with errors.Is and the
// values of golang.org/x/sys/unix, such as unix.ENXIO for a missing
// interface. On other systems the package is empty.
package netif
