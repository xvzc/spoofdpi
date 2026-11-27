//go:build darwin || freebsd

package route

// resolveLinks returns the links of the interfaces with indexes, read with
// lookup, in order. An interface whose link lookup fails is left out: it
// may have gone away since the routing table was read, as a VPN's
// interface does when it disconnects.
func resolveLinks(indexes []int, lookup func(int) (LinkInfo, error)) []LinkInfo {
	links := make([]LinkInfo, 0, len(indexes))
	for _, index := range indexes {
		link, err := lookup(index)
		if err != nil {
			continue
		}
		links = append(links, link)
	}
	return links
}
