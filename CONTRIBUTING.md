# Contributing to Vigilo

Thanks for your interest in Vigilo! Contributions of all sizes are welcome: bug reports, fixes,
documentation, prompts, and new features.

## Before you start

- **Bugs and ideas:** open an issue describing what you saw or what you would like to change.
  For anything larger than a small fix, please open an issue first so we can agree on the
  approach before you spend time on it.
- **Security vulnerabilities:** please do **not** open a public issue — follow
  [`SECURITY.md`](SECURITY.md) instead.
- Looking for something to work on? See
  [Next steps](README.md#next-steps--contributions-welcome) in the README.

## Making a change

1. Fork the repository and create a branch from `main`.
2. Set up a development environment as described in [Development](README.md#development).
3. Make your change. Keep it focused: one topic per pull request.
4. Add or update tests for the behaviour you changed, and update the README or docs if users
   would notice the difference.
5. Run the checks:

   ```bash
   uv run --frozen --all-extras --with pytest --with pytest-asyncio pytest tests
   cd web && npm run build      # if you touched the UI
   ```

6. Open a pull request explaining **what** changed and **why**, and link the related issue.

## Guidelines

- Never commit secrets, real credentials, or data from real scans. Use obviously fake values in
  tests and examples.
- Only test systems you are authorised to test, including while developing Vigilo.
- Follow the style of the surrounding code; small, readable changes are easier to review.

## Licence

By contributing, you agree that your contributions are licensed under the
[EUPL-1.2](LICENSE), the same licence as the project.
