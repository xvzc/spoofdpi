package livetest

import (
	"strings"
	"unicode"
)

// ServerFlag is a flag of the spoofdpi server command.
type ServerFlag struct {
	// Names are the flag's name and aliases, without dashes.
	Names []string
	// TakesValue is set for a flag that takes a value, that is, one that
	// is not a bool flag.
	TakesValue bool
}

// CaseFlags are the server flags a case may set (Allowed) and the ones
// livetest controls itself (Reserved).
type CaseFlags struct {
	Allowed  []ServerFlag
	Reserved []ServerFlag
}

// controlledFlags are the server flags a case cannot set, with why.
var controlledFlags = map[string]string{
	"no-tui":                 "set by livetest",
	"app-mode":               "set by livetest",
	"listen-addr":            "set by livetest",
	"log-level":              "set by livetest",
	"clean":                  "set by livetest",
	"config":                 "set by livetest",
	"auto-configure-network": "set by livetest",
	"help":                   "a case runs the server",
	"version":                "a case runs the server",
}

// SplitServerFlags sorts the server's flags into those a case may set and
// those livetest controls. A flag is controlled when any of its names is,
// so its aliases are controlled too.
func SplitServerFlags(flags []ServerFlag) CaseFlags {
	var split CaseFlags
	for _, f := range flags {
		if controlReason(f) != "" {
			split.Reserved = append(split.Reserved, f)
		} else {
			split.Allowed = append(split.Allowed, f)
		}
	}
	return split
}

func controlReason(f ServerFlag) string {
	for _, name := range f.Names {
		if reason, ok := controlledFlags[name]; ok {
			return reason
		}
	}
	return ""
}

// argFilter keeps the arguments of a case that spoofdpi may run with.
type argFilter struct {
	// flags maps every name of a server flag to how to filter it.
	flags map[string]filteredFlag
}

type filteredFlag struct {
	takesValue bool
	// reason is why a case cannot set the flag; empty if it can.
	reason string
}

func newArgFilter(flags CaseFlags) argFilter {
	f := argFilter{flags: map[string]filteredFlag{}}
	for _, sf := range flags.Allowed {
		for _, name := range sf.Names {
			f.flags[name] = filteredFlag{takesValue: sf.TakesValue}
		}
	}
	for _, sf := range flags.Reserved {
		reason := controlReason(sf)
		if reason == "" {
			reason = "set by livetest"
		}
		for _, name := range sf.Names {
			f.flags[name] = filteredFlag{takesValue: sf.TakesValue, reason: reason}
		}
	}
	return f
}

// filter returns the args without the flags a case cannot set, and a
// description of each argument it dropped. The value of a flag that takes
// one is the next argument, even if it starts with '-'. Other arguments
// that are not flags are dropped too: the server ignores them, and one
// that starts with '-', such as "-5", would end its flag parsing.
func (f argFilter) filter(args []string) (kept, ignored []string) {
	kept = []string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, hasValue, isFlag := parseFlagArg(arg)
		if !isFlag {
			ignored = append(ignored, "argument "+arg)
			continue
		}

		flag, known := f.flags[name]
		if !known {
			ignored = append(ignored, "unknown flag "+arg)
			continue
		}

		tokens := []string{arg}
		if flag.takesValue && !hasValue && i+1 < len(args) {
			i++
			tokens = append(tokens, args[i])
		}
		if flag.reason == "" {
			kept = append(kept, tokens...)
			continue
		}
		ignored = append(ignored, strings.Join(tokens, " ")+" ("+flag.reason+")")
	}
	return kept, ignored
}

// parseFlagArg reports whether arg is a flag the way the server's flag
// parser reads one ("--name", "-name", "--name=v" or "-name=v"), and
// returns its name and whether it has an "=v" part.
func parseFlagArg(arg string) (name string, hasValue, isFlag bool) {
	switch {
	case strings.HasPrefix(arg, "--"):
		name = arg[2:]
	case len(arg) > 1 && arg[0] == '-' && unicode.IsLetter(rune(arg[1])):
		name = arg[1:]
	default:
		return "", false, false
	}
	name, _, hasValue = strings.Cut(name, "=")
	return name, hasValue, true
}
