# Writing Test Code

This document describes the conventions for writing tests in spoofdpi. For how to run them, see [Running Tests](running-tests.md).

spoofdpi uses the standard `testing` package enhanced by [testify](https://github.com/stretchr/testify) for assertions and requirements. Follow the patterns established in `internal/config/*_test.go`.

## Framework

- Use `testify/assert` for general assertions where a failure should record an error but continue the test.
- Use `testify/require` only for checks that must pass for the rest of the test to proceed (e.g., checking for errors after a function call, ensuring setup was successful).
- Use `assert.NotSame` for `Clone` methods, and `assert.Panics` / `assert.NotPanics` for `Must*` functions.

```go
import (
    "testing"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

func TestExample(t *testing.T) {
    result, err := SomeFunction()

    // Stop immediately if there's an error
    require.NoError(t, err)

    // Assert the result, but continue even if it fails
    assert.Equal(t, "expected", result)
}
```

## Table-Driven Tests

For testing multiple scenarios of the same logic, **table-driven tests** are strongly preferred. This keeps the test code clean and makes it easy to add new cases.

```go
func TestCalculation(t *testing.T) {
    tcs := []struct {
        name     string
        input    int
        expected int
    }{
        {
            name:     "positive number",
            input:    5,
            expected: 10,
        },
        {
            name:     "zero",
            input:    0,
            expected: 0,
        },
    }

    for _, tc := range tcs {
        t.Run(tc.name, func(t *testing.T) {
            result := calculate(tc.input)
            assert.Equal(t, tc.expected, result)
        })
    }
}
```

Name the slice of cases `tcs`. Use an `assert func(t *testing.T, ...)` field for non-trivial output checks. Use separate inline `t.Run` blocks when the cases differ in structure and don't share a struct cleanly.

## Naming

- Method tests: `Test<Type>_<Method>` (e.g., `TestAppOptions_Clone`).
- Free-function tests: `Test<Function>` (e.g., `TestCheckDomainPattern`).
- Name table-driven cases with lowercase phrases (e.g., `"nil receiver"`, `"default values (no flags)"`).
- Tests that need root call `testutil.RequireRoot(t)` and end their name in `RequireRoot` (e.g., `TestSenderLive_LocalConnection_RequireRoot`). See [Root-Privileged Tests](running-tests.md#root-privileged-tests).

## Values and Coverage

- Use `lo.ToPtr(...)` from `github.com/samber/lo` for optional pointer fields.
- Cover success cases, edge cases, and failure cases. Include a `"nil receiver"` case for methods that accept a receiver.
