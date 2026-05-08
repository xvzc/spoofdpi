# Agent Configuration

This file is the single source of truth for shared agent configuration. Read the instructions below and generate the appropriate local config file for your agent (e.g. Claude Code `settings.json`).

When a configuration change is requested, follow these rules:

1. Present a selection box with exactly two options: a. Personal, b. Project-wide. Do this using the AskUserQuestion tool.
2. Permission-related changes are always treated as personal — skip the prompt and apply directly as personal.
3. Personal changes: apply to the agent-specific config only (e.g. `settings.json`). Do not touch this file.
4. Project-wide changes: update this file first, then apply to the agent-specific config.

## Setup

Wire `.agents/` into your agent using symlinks named as each agent expects. Do not copy files — always symlink so `.agents/` stays the single source of truth.

Generate the agent-specific config file (e.g. `settings.json`) from the **Allowed commands** and **Hooks** sections below. Do not symlink it — create it as a real file in the agent-specific directory. The generated file is gitignored and local to each developer.

Symlink the instruction file to wherever your agent expects it. Examples:
- Claude Code: `ln -s .agents/AGENTS.md .claude/CLAUDE.md`
- Root-level agents: `ln -s .agents/AGENTS.md AGENTS.md`

**Never symlink the entire `.agents/` directory.** Always symlink subdirectories individually (`rules/`, `skills/`, `commands/`). Symlinking the whole directory risks exposing `settings.json` to version control.

If the agent-specific directory (e.g. `.claude/`) does not exist, create it automatically. For each of `rules/`, `skills/`, `commands/`: if the subdirectory does not exist in `.agents/`, skip it.

- `skills/` — behaviors that trigger automatically based on context
- `rules/` — project rules the agent must follow
- `commands/` — custom commands the user can invoke explicitly

## Hooks

Automation that runs at specific points in the agent's tool execution lifecycle.

### Pre tool use
- `git commit *` → `task pre-commit` (timeout: 180s)
