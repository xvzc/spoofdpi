package config

import "sync"

var (
	warnMu   sync.Mutex
	WarnMsgs []string
)

func AddWarnMsg(msg string) {
	warnMu.Lock()
	WarnMsgs = append(WarnMsgs, msg)
	warnMu.Unlock()
}
