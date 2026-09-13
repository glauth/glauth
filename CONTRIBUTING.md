# Contributing to GLAuth

Thanks for your interest in improving GLAuth! This guide covers how to set up your environment, submit changes, and work with the maintainers. Starting with GLAuth 2.4.0, we reworked and optimized the build workflow, and this contribution process reflects that.

## Getting Started

1. Fork the repository and clone your fork locally.
2. Review the [Building](https://glauth.github.io/docs/building.html) docs to compile GLAuth from source.
3. Review the [Testing](https://glauth.github.io/docs/testing.html) docs to run the test suite before submitting changes.
4. Create a topic branch for your work off of `master`.

## Reporting Issues

- Open an issue on the [GLAuth issue tracker](https://github.com/glauth/glauth/issues) for bugs and feature requests.
- Include your GLAuth version, configuration (with secrets redacted), and clear steps to reproduce.

## Preparing to Commit

Format your code automatically using `gofmt -d ./` before committing. If you forget this step, a subsequent pull request may fail.

## Writing Commit Messages

Commit messages must be semantically correct. We follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

A commit message contains a prefix, followed by a short explanation. It may also contain "footer" annotations, but these are not mandatory (though appreciated).

Please don't bundle multiple unrelated items in the same commit (e.g., a new feature and a bug fix).

### Commit Prefix

A prefix is written imperatively, for example:

```
feat(plugins)!: Change the plugins API to allow NoSQL databases.
```

This is a new feature (`feat`), optionally scoped to an area of GLAuth (`(plugins)`), with `!` warning of a breaking change.

A more innocuous change:

```
chore: Add more comments in all modules.
```

Available prefixes: `feat`, `fix`, `chore`, `build`, `ci`, `perf`, `refactor`, `test`, `style`.

### Commit Footer Annotations

For example:

```
Reviewed-by: John Romero <john@romero.com>
Tested-by: Joel Spolsky <joel@joelonsoftware.com>
BREAKING-CHANGE: I broke the plugin
