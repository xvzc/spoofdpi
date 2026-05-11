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
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	return string(out), err
}
