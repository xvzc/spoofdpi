# Agent Setup

Shared agent configuration lives in `.agents/`. Each developer wires it into their own agent via symlinks — never by copying files. `.agents/CONFIG.md` is the single source of truth.

You can also automate the setup by prompting your agent:

> Set up my agent config by referencing `.agents/CONFIG.md`

## Claude Code

Create the `.claude/` directory and symlink the shared config into it:

```console
$ mkdir -p .claude
$ ln -s ../.agents/AGENTS.md .claude/CLAUDE.md
$ ln -s ../.agents/rules .claude/rules
$ ln -s ../.agents/skills .claude/skills
```

Then generate `.claude/settings.json` by following the instructions in `.agents/CONFIG.md`. This file is gitignored and stays local to your machine.

## Other Agents

For root-level agents (e.g. Gemini CLI):

```console
$ ln -s .agents/AGENTS.md AGENTS.md
```

Symlink `rules/`, `skills/`, and `commands/` subdirectories wherever your agent expects them. **Never symlink the entire `.agents/` directory** — always symlink subdirectories individually to avoid exposing `settings.json` to version control.
