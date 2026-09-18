# Security Policy

## Reporting a vulnerability

This is a small, actively-maintained home-lab/portfolio project, but if
you find a genuine security issue — something that could let network
traffic bypass detection undetected, an injection point in how alerts are
constructed, or anything similar — please report it privately rather than
opening a public issue.

**How to report:**
- Use [GitHub's private vulnerability reporting](https://github.com/ER723/recon-detector/security/advisories/new)
  (Security tab → Report a vulnerability), or
- Email asukmana723@gmail.com with details and, if possible, steps to
  reproduce.

Please don't open a public issue for anything that could be actively
exploited before a fix is available.

## Scope

This tool sniffs and analyzes network traffic, and `deploy/` contains
systemd service definitions and OSSEC HIDS decoder/rule config for
production deployment — vulnerabilities in how it parses untrusted
traffic, or in those deployment configs, are in scope. General "this
heuristic missed a scan" reports are welcome as regular issues (see
[CONTRIBUTING.md](CONTRIBUTING.md)), not security reports — this project's
[Limitations](README.md#limitations-read-before-relying-on-this) section
already documents that detection gaps are expected, not vulnerabilities.

## Response

I'll acknowledge reports within a few days and let you know if/when a fix
lands. This is a solo-maintained project, so please be patient.
