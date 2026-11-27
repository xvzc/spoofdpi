package executil

import (
	"fmt"
	"os/exec"

	"mvdan.cc/sh/shell"
)

func Commandf(format string, args ...any) (string, error) {
	return Command(fmt.Sprintf(format, args...))
}

func Command(cmd string) (string, error) {
	args, err := shell.Fields(cmd, nil)
	if err != nil {
		return "", err
	}
	if len(args) == 0 {
		return "", nil
	}
	return Run(args[0], args[1:]...)
}

// Run runs name with args, without a shell, and returns its combined output.
func Run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}
