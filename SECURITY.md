# Security Policy

## Overview

**RESX** analyzes untrusted Windows binaries, symbols, rules, and corpora. Its primary security objective is simple: analysis input must not execute code, escape intended file access, corrupt the host, or compromise applications using the RESX DLL.

RESX maintains a STRIDE threat model and an adapted Microsoft SDL process.

- [Threat Model](docs/security/threat-model.md)
- [Secure Development Lifecycle](docs/security/sdl.md)

## Supported Versions

Security updates cover the latest stable release and the immediately preceding minor version. Older versions receive fixes only for critical issues.

See [Releases](https://github.com/Ryftenius/RESX/releases) for supported builds.

## Reporting a Vulnerability

Report vulnerabilities privately so we can investigate and coordinate disclosure.

**Preferred method:** email [security@ryftenius.com](mailto:security@ryftenius.com).

Include:

- Impact and affected component.
- Affected version and configuration.
- Reproduction steps.
- Proof of concept, crash dump, or logs where useful.
- Relevant threat-model or SDL references.

Avoid sending a full exploit in the first email. GitHub Private Vulnerability Reporting is also supported.

### What to Expect

- **Acknowledgment:** within 72 hours.
- **Updates:** every 7–14 days, depending on severity.
- **Fix target:** 30–90 days for confirmed critical issues, depending on complexity.
- **Credit:** included unless you prefer anonymity.

We follow coordinated responsible disclosure. Details remain private until a fix is available and the timeline is agreed.

## Security Advisories and CVEs

Confirmed vulnerabilities are published through GitHub Security Advisories. Advisories may include a CVE, affected versions, fixed versions, mitigations, and threat-model references.

## Non-Security Issues

Use the repository's Issues or Discussions for bugs, features, and general questions.
