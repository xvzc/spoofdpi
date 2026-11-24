# Documentation

The project documentation is built with [MkDocs](https://www.mkdocs.org) and the [Material for MkDocs](https://github.com/squidfunk/mkdocs-material) theme.

## Setup

Install the theme. `mkdocs-material` installs MkDocs as a dependency.

```console
$ pip install mkdocs-material
```

## Local Development

All documentation source files are located in the `docs` directory, and the configuration file `mkdocs.yml` is located in the project root.

To run the documentation site locally, execute the command below from the project root:

```console
$ mkdocs serve
```

This command will start a development server (usually accessible at `http://127.0.0.1:8000`), which automatically reloads upon source file changes.

## When to Update the Docs

Update the docs when a change adds, removes, or renames a config option, or changes user-observable runtime behavior. Pure refactors and internal changes don't need a doc update.

Where each topic goes:

- `docs/user-guide/`: config options and runtime behavior.
- `docs/getting-started/`: install, quick start, and introduction.
- `docs/developer-guide/`: build, test, lint, and commit workflow.
