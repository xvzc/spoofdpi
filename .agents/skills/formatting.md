# formatting

## When to apply

Apply at the end of each implementation unit — when the agent considers a task or subtask complete before reporting back to the user.

## Steps

1. Run `golangci-lint fmt` from the project root.
2. Run `golangci-lint run` from the project root (config lives in `.golangci.yml`).

If lint fails, fix the issues before reporting the task as complete.
