# Security Policy

The BloxTools Studio plugin uploads your game's source code, so its security
model is the whole point. This document explains that model and how to report
problems.

## The design in one paragraph

The plugin is **zero-knowledge**: your project key is generated in the dashboard,
pasted into the plugin once, and stored only in Studio's per-user plugin settings
on your own disk. Source is encrypted **client-side** with AES-256-GCM before it
ever leaves Studio; the backend stores only ciphertext. The key never travels —
only an 8-hex-character SHA-256 fingerprint of it does. Decryption happens only
where you supply the key: in your browser (the dashboard) or on your own machine
(the [BloxTools MCP server](https://github.com/bloxtoolsio/bloxtools-mcp)). See
[TRUST.md](TRUST.md) for how to verify every part of this yourself.

The plugin requests exactly **one** permission: HTTP access to the single backend
domain you configure. It never requests Script Injection and never writes to your
scripts.

## What to report privately

Please report the following through the private channel below rather than a
public issue:

- A plugin build that prompts for **Script Injection** or for a **second HTTP
  domain** you did not configure.
- A released `BloxToolsPlugin.rbxm` whose SHA-256 does **not** match the hash in
  its GitHub release notes, or that does not reproduce from the tagged source.
- Any way the plugin could leak your **project key**, your **access token**, or
  **plaintext source** to the network, logs, or any third party.
- Any cryptographic flaw in `src/Crypto/` or its `tools/` mirror.

Ordinary bugs, feature requests, and questions can go in public GitHub issues.

## How to report

Use **GitHub's private vulnerability reporting** for this repository:
**Security → Report a vulnerability** (the "Report a vulnerability" button on the
repo's Security tab). This opens a private advisory visible only to the
maintainers.

Please include:

- a description of the issue and its impact,
- steps to reproduce (or a proof of concept),
- the plugin version / release tag or commit, and your Studio + OS versions.

We aim to acknowledge reports within a few business days. Please give us a
reasonable window to ship a fix before any public disclosure.

## Supported versions

Security fixes target the latest released version. Always install the most
recent `BloxToolsPlugin.rbxm` from the
[releases page](https://github.com/bloxtoolsio/bloxtools-plugin/releases), and
verify its hash per [TRUST.md](TRUST.md#verifying-a-release).
