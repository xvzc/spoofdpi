# testing

## When to apply

Apply at the end of each implementation unit — when the agent considers a task or subtask complete before reporting back to the user.

## Steps

Run `go test -tags network ./...` from the project root. Use `go test ./...` only when network-dependent tests must be excluded (e.g. sandboxed Nix builds).

If any tests fail, do not report the task as complete. Fix the failures first.
