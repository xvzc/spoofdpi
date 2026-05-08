# Security

## Credentials

Never hardcode credentials, API keys, tokens, or any secret values in source code, configuration files, or settings files.

Never stage or commit files that may contain secret values — including `.env`, `*.pem`, `*.key`, `*secret*`, `*credential*`, and any file explicitly excluded in `.gitignore`. If such a file is found in the staging area, warn the user and remove it before proceeding.

## Paths

Never hardcode absolute paths containing usernames or system-specific directories.
This applies to all files including source code, configuration, and settings files.

```go
// incorrect
path := "/Users/username/personal/spoofdpi/internal"

// correct
home, _ := os.UserHomeDir()
path := filepath.Join(home, ".spoofdpi")
```

```json
// incorrect
{ "command": "cd /Users/username/personal/spoofdpi && go test ./..." }

// correct
{ "command": "go test ./..." }
```
