# Contributing to RESX

Keep changes focused. Add tests for new behavior and update the affected documentation.

## Development Checks

Before pushing Rust changes:

```powershell
cargo fmt -p resx -- --check
cargo clippy -p resx --all-targets -- -D warnings
cargo test -p resx
```

Before pushing VS Code extension changes:

```powershell
cd resx-vscode
npx tsc -p ./ --noEmit
npx tsc -p ./tsconfig.webview.json --noEmit
node --experimental-default-type=module ./test/run-tests.mjs
```

Before packaging the extension:

```powershell
cd resx-vscode
npm run compile
npm run package
```

`resx-vscode/bin/`, `target/`, `target-resx-tests/`, generated packages, and local signing/build artifacts are ignored by Git.

## Pull Requests

- Explain the change and its test coverage.
- Keep unrelated changes out.
- Do not commit generated binaries, packages, symbols, or local analysis artifacts.
- Report security issues through [SECURITY.md](SECURITY.md), not a public issue.
