# Code Quality

This project utilizes [golangci-lint](https://github.com/golangci/golangci-lint) as the **single entry point** for both code quality checks (linting) and style enforcement (formatting). This ensures consistent code standards across the entire project.

Format the code with the formatters configured in `.golangci.yml`:

```console
$ golangci-lint fmt
```

Run all quality checks:

```console
$ golangci-lint run
```
