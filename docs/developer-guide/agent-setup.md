# Agent Setup

Shared agent configuration lives in `.agents/`.

## Claude Code

```console
$ make claude
```

## Other Agents

Symlink `.agents/AGENTS.md` and `.agents/rules/` wherever your agent expects them.

If you use a different agent, consider contributing a `make <agent>` target to the `Makefile` so others can get started with one command.
