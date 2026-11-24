# AGENTS.md

How to run the root-privileged and end-to-end tests, what each check means, and the rules for
those runs are in `docs/developer-guide/running-tests.md`. Follow them, and also:

- Ask a human to type the sudo password or approve the request before a root
  command, and say which command needs it.
- Report the results per OS in the form below.

## Reporting Results

Quote the lines as printed:

```text
os: <uname -sr>, host: <hostname>, commit: <git rev-parse --short HEAD>
root-privileged tests: <ok or FAIL line per package that ran tests>
  failures: <--- FAIL lines with their output, or none>
  skips: <--- SKIP lines with their reason>
nonroot: <--- PASS/FAIL line>
e2e: <ok or FAIL line>
  <--- PASS/FAIL line per check, with its logged evidence>
artifacts: <paths>
left running: <pgrep output, or none>
```

Do not summarize a failure away: add the evidence from the artifacts. A `SKIP` is
not a failure, but give its reason.
