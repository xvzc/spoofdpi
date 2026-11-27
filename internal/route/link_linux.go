package route

import "fmt"

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
