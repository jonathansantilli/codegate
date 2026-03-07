# Contributing to CodeGate

Thanks for contributing.

## Development Workflow

1. Fork and clone the repository.
2. Create a topic branch from `main`.
3. Install dependencies:
   ```bash
   npm install
   ```
   This also installs the Husky-managed `pre-commit` hook, which runs staged-file linting and formatting before a commit is created.
4. Run local verification before pushing:
   ```bash
   npm run lint
   npm run typecheck
   npm run test
   npm run build
   ```
5. Open a pull request with:
   - clear problem statement
   - implementation summary
   - test evidence

## Commit Guidelines

- Use focused commits.
- Prefer Conventional Commit prefixes (`feat:`, `fix:`, `docs:`, `test:`, `chore:`).
- Keep unrelated changes out of the same PR.

## Pull Request Expectations

- Add or update tests for behavior changes.
- Update docs for user-visible changes.
- Keep CI green.

## Reporting Security Issues

Please do not open public issues for vulnerabilities.
See [SECURITY.md](./SECURITY.md) and follow the private disclosure process.
