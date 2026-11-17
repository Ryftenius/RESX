# Contributing

Welcome to RESX! Contributors are welcome. This document is for you if you want to help build RESX. If you just want to use it, start with the [README](README.md) and the [command reference](COMMANDS.md).

## Overview

Here are the ways you can help, in no particular order. Each one is covered in more detail below.

- [Build RESX](#build-resx) and add features or fix bugs. Issues labelled `good first issue` are a good place to start.
- [Report bugs](#report-bugs) or [request features](#request-features) on the [issue tracker](https://github.com/Ryftenius/RESX/issues).
- [Contribute a test fixture](#contribute-test-fixtures) for a technique RESX misses or gets wrong.
- [Write a tested example](#write-a-tested-example) for the README showcase.
- [Improve the documentation](#improve-the-documentation).
- [Triage issues](#triage-issues) by reproducing reports and asking for missing details.

Found a security vulnerability? **Do not open a public issue.** Follow the [security policy](SECURITY.md) and report it privately through a [GitHub Security Advisory](https://github.com/Ryftenius/RESX/security/advisories/new).

### AI Policy

We welcome the use of LLMs for coding, but we hold a high bar for all contributions, and **we expect a human in the loop who genuinely understands the work an LLM produces** on their behalf. For that reason, we **don't accept contributions from autonomous agents**. Pull requests that appear to violate this may be closed, sometimes without notice.

This matters more than usual for RESX. It analyzes hostile binaries, so a plausible-looking change to a parser, a bound or a heuristic can open a crash, a hang or a misleading result to anyone who feeds it a crafted sample. You must be able to explain why your change is correct on adversarial input, not just on the sample in front of you.

**Don't rely on LLMs to write the whole thing for you when communicating with the maintainers** (meaning replies to comments, PR descriptions, and alike). The readers are humans, and we'd like to hear from you, not from a model. If you're a non-native English speaker using an LLM to thoroughly edit or translate your messages to the maintainers, we'd encourage you to **put the machine translation in a quote block and include the original text in your native language after it**.

If you think it's helpful or necessary to **share context from a chat with an LLM**, put the **relevant part of it** in a quote block (for example using `>`), **disclose it as AI-generated**, and add your own commentary explaining **why it's relevant and what you take from it**.

This policy was adapted from [x64dbg's AI policy](https://github.com/x64dbg/x64dbg/blob/development/CONTRIBUTING.md#ai-policy), itself adapted from [Zed's AI policy](https://github.com/zed-industries/zed/blob/35eaeb94a7e5e9dcd7384df4bd21f01c30a38a09/CONTRIBUTING.md#ai-policy).

### Build RESX

RESX is a Rust workspace that targets Windows. The README covers [building the CLI](README.md#build-the-cli) and the [DLL / FFI](README.md#use-the-dll--ffi). In short:

```powershell
git clone https://github.com/Ryftenius/RESX.git
cd RESX
cargo build -p resx --release
```

Before you open a pull request, run the same checks CI runs:

```powershell
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

#### Getting started with development

The code can look daunting at first. These documents explain how it fits together:

- [Architecture](docs/architecture.md) (**must read**): image facts, analysis sessions, providers and the command layer. Commands pick analyses and render results; they shouldn't do analysis themselves.
- [Security policy](SECURITY.md) (**must read**): every sample is treated as adversarial. Know the trust boundaries before you touch parsing or I/O.
- [Analysis surfaces](docs/analysis-surfaces.md): what RESX looks at and how far each analysis goes.
- [CLI documentation](docs/cli.md): option groups, command grammar and earlier spellings.
- [JSON schemas](docs/json-schemas.md): the versioned output contract and its stability rules.
- [DLL / FFI](docs/dll.md) for the native integration layer.

#### Ground rules for code changes

- **Assume hostile input.** Every header, offset, size, RVA, name and record in a sample can lie. Use the checked readers and section mappings, bound every loop and allocation, and never turn missing bytes into zeroes. A sample must not be able to crash RESX, hang it, exhaust memory, or make it read or execute anything on the analyst's machine.
- **Report evidence, not conclusions.** Findings describe what code *can* do, with its location, confidence and source. Don't claim something executed, and keep unknown values unknown.
- **Keep the CLI grammar consistent.** Options belong to the command that uses them, in `resx/src/cli/args.rs`, and the help text is generated from it. Renamed options keep their earlier spelling as a hidden alias, which the `legacy_spellings_still_parse` test enforces.
- **Keep JSON stable.** Within a schema version, only add optional fields. Don't change a field's representation, and expose limits and truncation when a bound is hit.
- **Test what you fix.** Add a unit test, or a fixture under `resx/tests/data` with an integration test that pins down the behavior.
- **Record public changes** in [CHANGELOG.md](CHANGELOG.md), in the same style as the existing entries.

#### Sending a pull request

Here is a short guide for anyone new to git:

1. [Fork](https://github.com/Ryftenius/RESX/fork) the RESX repository to your GitHub account.
2. Clone your fork:
   ```sh
   git clone https://github.com/<yourusername>/RESX.git
   ```
3. Create a [feature branch](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/about-branches) to isolate your changes:
   ```sh
   git checkout -b my-feature
   ```
4. Make your changes, run the checks above, then add the files to the [staging area](https://git-scm.com/about/staging-area):
   ```sh
   git add <files>
   ```
5. Create a [commit](https://docs.github.com/en/pull-requests/committing-changes-to-your-project/creating-and-editing-commits/about-commits). RESX uses conventional commit messages with a scope, for example:
   ```sh
   git commit -m "fix(resolution): recover encoded manual export lookups"
   ```
6. Push the branch to your fork:
   ```sh
   git push --set-upstream origin my-feature
   ```
7. Open your fork on GitHub and click **Compare & pull request**. Describe what changed and why, how you tested it, and any sample or fixture it relies on.

For a more in-depth tutorial, see GitHub's [contributing to a project](https://docs.github.com/en/get-started/exploring-projects-on-github/contributing-to-a-project) guide.

Happy PRs!

### Report bugs

To give your report the best chance of being fixed, put in some effort up front:

1. Search the [issue tracker](https://github.com/Ryftenius/RESX/issues) to check the bug hasn't already been reported.
2. Give the exact command and options, and concrete steps to reproduce it.
3. Include `resx --version` and your Windows build.
4. Say what you expected and what happened instead. For wrong analysis, the relevant `--json` output or a short excerpt helps a lot.
5. Attach a sample that reproduces the problem **only if it is safe and legal to share**. Prefer a minimal, inert binary over a live sample, and never attach live malware to a public issue. `--debug-report <REPORT.ZIP>` writes a sanitized reproducibility bundle; it leaves out the target's bytes unless you add `--debug-report-include-target`.

A crash, hang or runaway resource use caused by a sample is a security issue. Report it privately, as described in the [security policy](SECURITY.md).

### Request features

A clear request is far more likely to be picked up. Describe the behavior you want and give concrete examples of when it would help, ideally a technique RESX misses together with how you would expect it to be reported. Requests outside the project's scope, which is static analysis of Windows binaries, may be closed. Opening an issue is still the best way to raise an idea.

### Contribute test fixtures

Many of RESX's improvements start from a technique it doesn't recognize yet. The most useful fixture is a small program that reproduces the technique and nothing else, like [`manual_resolver.c`](resx/tests/data/manual_resolver.c) and [`hash_resolver.c`](resx/tests/data/hash_resolver.c).

- Check in the C source alongside the compiled binary, and include the build command in the source comments or the pull request.
- Keep fixtures **inert**: no payloads, no network, no persistence, and nothing that changes the system. Any executable memory should hold only a `RET` and never be called. Print lengths or counts rather than collected data.
- Build without a PDB unless the test is about symbols, so the test exercises static recovery.
- Add an integration test under `resx/tests/` that runs the CLI with `--json` and asserts the recovered evidence. See `manual_export_resolution.rs` and `hash_api_resolution.rs`.
- Never submit live malware or binaries you don't have the right to redistribute.

### Write a tested example

The README showcase is built from tested examples: a small, reproducible scenario, the exact commands, real RESX output, and an honest account of what it shows. When an example compares RESX with another tool, use the other tool's real output with default analysis, and state any limits RESX has on the same input. Name the versions you tested with.

### Improve the documentation

If you see room for improvement in the README, the [command reference](COMMANDS.md) or anything under [`docs/`](docs), send a pull request. Keep documentation accurate to what the code does today; if behavior changed, update the docs in the same pull request.

### Triage issues

You can help by reproducing bug reports, asking for missing details such as the version, the command or a safe sample, and confirming fixes. Comment on an issue with what you found, including your RESX version and Windows build.
