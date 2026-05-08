# AGENTS.md

## Project

spoofdpi is a proxy tool that bypasses Deep Packet Inspection (DPI) — the technique used by many internet censorship systems to inspect and block traffic. It works by fragmenting and desynchronizing TLS handshakes so that DPI middleboxes misparse the connection while the destination server handles it normally.

## Agent configuration

All shared agent configuration lives in `.agents/`. This includes rules, skills, and commands. Each developer wires these into their own agent by creating symlinks — never by copying files.

`.agents/CONFIG.md` is the single source of truth for configuration. Read it to understand what permissions and hooks to set up, and to generate your local agent config file (e.g. `settings.json`).

Configuration changes are applied to the local agent config only by default. `.agents/CONFIG.md` is updated only when a change is explicitly intended to be shared with the team.
