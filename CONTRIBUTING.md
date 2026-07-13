# Contributing to computermoney

Thanks for your interest in contributing.

## Developer Certificate of Origin (DCO)

Every commit must be signed off under the
[Developer Certificate of Origin 1.1](https://developercertificate.org).
By signing off, you certify that you wrote the change or otherwise have
the right to submit it under this project's license.

Add a sign-off to each commit:

```sh
git commit -s
```

which appends a line like:

```
Signed-off-by: Your Name <you@example.com>
```

Pull requests containing unsigned commits fail the DCO check and cannot
be merged.

## Ground rules

- Code, comments, commit messages, issues, and PRs are in English.
- Run `cargo test` before submitting.
- Keep changes small and focused. Security-sensitive code (key handling,
  policy, chain, storage) gets extra scrutiny.

## License

By contributing, you agree that your contributions are licensed under the
MIT License (see [LICENSE](LICENSE)). The "computermoney" name is not
covered by the code license — see [TRADEMARK.md](TRADEMARK.md).
