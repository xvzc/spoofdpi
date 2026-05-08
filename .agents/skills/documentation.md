# documentation

## When to apply

Apply at the end of each implementation unit — when the agent considers a task or subtask complete before reporting back to the user.

## Steps

Review the changes made and decide whether any user-visible behavior was affected. Update `docs/` when the change:
- adds, removes, or renames a config option (CLI flag, TOML key, env var, default value)
- changes runtime behavior a user can observe (proxy modes, DNS resolution, fake-packet behavior, TUI interactions, exit codes, log output users rely on)
- changes install, build, or run instructions

Pure refactors, internal renames, test-only changes, and implementation details that don't affect the public surface do **not** require doc updates.

If a doc update is needed, make the changes directly. Place them in the section that matches the change:
- `docs/user-guide/` — config options and runtime behavior
- `docs/getting-started/` — install, quick-start, introduction
- `docs/developer-guide/` — build/test/lint workflow, commit conventions

If unsure whether a change is user-visible, default to no doc update and mention it to the user.
