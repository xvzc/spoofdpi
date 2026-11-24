package netutil

import (
	"errors"
	"fmt"
)

// linkInfo returns the link of the interface with index, read with
// RTM_GETLINK.
func linkInfo(index int) (LinkInfo, error) {
	seq := netlinkSeq.Add(1)
	reply, err := netlinkRequest(encodeLinkGet(seq, index), seq, false)
	if err != nil {
		return LinkInfo{}, fmt.Errorf("link %d: %w", index, err)
	}
	return linkInfoFromNetlink(reply, index)
}

// defaultLinks returns the links of the unicast default routes of fam in
// every routing table, in dump order and without duplicates. A default
// whose link cannot be read is left out. A dump that a concurrent route
// change interrupts is tried once more.
func defaultLinks(fam Family) ([]LinkInfo, error) {
	var reply []netlinkMessage
	var err error
	for range 2 {
		seq := netlinkSeq.Add(1)
		reply, err = netlinkRequest(encodeRouteDump(seq, fam), seq, true)
		if !errors.Is(err, errNetlinkDumpInterrupted) {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%s default routes: %w", fam, err)
	}
	oifs, err := defaultRouteOifs(reply, fam)
	if err != nil {
		return nil, fmt.Errorf("%s default routes: %w", fam, err)
	}

	return resolveLinks(oifs, linkInfo), nil
}
