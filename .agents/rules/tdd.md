# TDD

TDD is the default development approach. If TDD is clearly inappropriate for a given task (e.g. exploratory work, pure refactoring with existing tests), ask the user for permission to skip before proceeding.

## Workflow

### 1. Natural language design

Describe the types, interfaces, and function signatures in plain language — no code yet. Present to the user and iterate based on feedback until approved.

### 2. Natural language test scenarios

List the test scenarios in plain language (happy path, edge cases, failure cases). Present to the user and iterate based on feedback until approved.

### 3. Red

Write the test code based on the approved scenarios. Run the tests and confirm they fail. If a test passes without any implementation, the test is wrong — fix it before proceeding.

### 4. Green

Write the minimum implementation needed to make the tests pass. Run the tests and confirm they all pass.

### 5. Refactor

Clean up the code while keeping all tests green.

## Conventions

These conventions follow the patterns established in `internal/config/*_test.go`. Apply them to new tests; only deviate when there is a clear, code-specific reason.

### Naming

- Method tests: `Test<Type>_<Method>` — e.g. `TestAppOptions_UnmarshalTOML`, `TestAppOptions_Clone`, `TestAppOptions_Merge`.
- Free-function tests: `Test<Function>` — e.g. `TestCheckDomainPattern`, `TestMustParseBytes`.
- Subtest names use lowercase phrases describing the scenario: `"valid general options"`, `"nil receiver"`, `"merge values"`, `"invalid type"`.

### Table-driven tests

Default to table-driven. The slice is always named `tcs`, never `tests` / `cases`:

```go
tcs := []struct {
    name    string
    input   any
    wantErr bool
    assert  func(t *testing.T, o AppOptions)
}{
    // ...
}

for _, tc := range tcs {
    t.Run(tc.name, func(t *testing.T) {
        var o AppOptions
        err := o.UnmarshalTOML(tc.input)
        if tc.wantErr {
            assert.Error(t, err)
        } else {
            assert.NoError(t, err)
            if tc.assert != nil {
                tc.assert(t, o)
            }
        }
    })
}
```

Common struct fields (use the names that fit the test, not all of them):
- `name string` — required
- `input` — input value, typed appropriately
- `expected` — expected value when comparison is a single equality
- `wantErr bool` — expected error flag
- `wantPanic bool` — for `Must*` functions
- `assert func(t *testing.T, ...)` — closure for non-trivial output verification (multi-field structs, pointer identity, etc.)
- For `Merge`: `base`, `override`, `assert`
- For `Clone`: `input`, `assert(t, input, output)` so the closure can verify identity vs. value

For simple validators where each case is just `(name, input, wantErr)`, use compact positional literals:

```go
tcs := []struct {
    name    string
    input   string
    wantErr bool
}{
    {"valid domain", "example.com", false},
    {"invalid empty", "", true},
}
```

### When inline `t.Run` is acceptable

When a test needs a handful of distinctly-shaped scenarios that don't share a struct cleanly (e.g. parsing different TOML snippets), inline `t.Run` blocks are fine — see `TestSegmentPlan_UnmarshalTOML`. Don't force a table when each case is structurally different.

### Assertions

- Use `github.com/stretchr/testify/assert` for normal checks.
- Use `github.com/stretchr/testify/require` only when subsequent code in the test cannot meaningfully run on failure (setup invariants, "function never called"). See `internal/config/cli_test.go` for examples.
- Use `assert.NotSame` to verify `Clone` returns a distinct pointer.
- Use `assert.Panics` / `assert.NotPanics` for `Must*` functions.

### Constructing values

- Build optional pointer fields with `lo.ToPtr(...)` from `github.com/samber/lo`. Do not write `func() *T { v := x; return &v }()` helpers.
- Build `*net.TCPAddr` with explicit `&net.TCPAddr{IP: net.ParseIP(...), Port: ...}`.

### Coverage

Each function should have tests covering: happy path, edge cases, and failure cases. For `UnmarshalTOML` always include an `"invalid type"` case; for `Clone` always include a `"nil receiver"` case; for `Merge` always include `"nil receiver"` and `"nil override"` cases.

### Section grouping

When a single `_test.go` file covers multiple related types, separate them with ASCII box headers (matches `types_test.go`):

```go
// ┌─────────────────┐
// │ GENERAL OPTIONS │
// └─────────────────┘
```

### Parallelism

Current config tests do not use `t.Parallel()`. Don't add it unless the rest of the suite is being migrated together — mixing parallel and serial tests in the same package can mask shared-state bugs.
