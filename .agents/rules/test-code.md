# Test Code Conventions

Follow the patterns established in `internal/config/*_test.go`.

## Naming

- Method tests: `Test<Type>_<Method>` — e.g. `TestAppOptions_Clone`
- Free-function tests: `Test<Function>` — e.g. `TestCheckDomainPattern`
- Subtest names: lowercase phrases — e.g. `"nil receiver"`, `"invalid type"`

## Table-driven tests

Default to table-driven. The slice is always named `tcs`:

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

Use an `assert func(t *testing.T, ...)` field for non-trivial output verification. Use inline `t.Run` blocks when cases are structurally different and don't share a struct cleanly.

## Assertions

- `assert` for normal checks, `require` only when the test cannot meaningfully continue on failure.
- `assert.NotSame` for Clone, `assert.Panics` / `assert.NotPanics` for `Must*` functions.

## Constructing values

Use `lo.ToPtr(...)` from `github.com/samber/lo` for optional pointer fields.

## Coverage

Cover success cases, edge cases, and failure cases. Include a `"nil receiver"` case for methods that accept a receiver.
