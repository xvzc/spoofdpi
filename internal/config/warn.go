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

// scopeWarnings runs fn and prefixes the warnings it adds with scope, so
// that a warning raised while parsing a rule says which rule it is about.
func scopeWarnings(scope string, fn func() error) error {
	warnMu.Lock()
	start := len(WarnMsgs)
	warnMu.Unlock()

	err := fn()

	warnMu.Lock()
	for i := start; i < len(WarnMsgs); i++ {
		WarnMsgs[i] = scope + ": " + WarnMsgs[i]
	}
	warnMu.Unlock()

	return err
}
