package livetest

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
)

// The checks below validate livetest's flags. Their errors do not name the
// flag: the flag parser adds it.

// checkListen accepts an ip:port address that spoofdpi's --listen-addr
// accepts.
func checkListen(v string) error {
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return err
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("%q is not an IP address", host)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("%q is not a port number", port)
	}
	return nil
}

// checkURLs accepts http and https URLs with a host.
func checkURLs(urls []string) error {
	for _, v := range urls {
		u, err := url.Parse(v)
		if err != nil {
			return err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("%q: scheme must be http or https", v)
		}
		if u.Host == "" {
			return fmt.Errorf("%q: host is missing", v)
		}
	}
	return nil
}

// checkConfigFile accepts an existing regular file.
func checkConfigFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%q is not a regular file", path)
	}
	return nil
}
