# Security policy

## What this tool does and does not do

- The collector (`collector/Collect-E8Evidence.ps1`) **only reads** configuration. It changes no
  settings, installs nothing and makes no network connections.
- The analyser treats the evidence file as untrusted input: every value is escaped before it is
  written into an HTML report, and malformed files produce an error rather than a crash.
- Evidence files contain hostnames, usernames and installed software. Treat them as internal
  information and do not commit them to public repositories (`.gitignore` already excludes the
  default file names).

## Reporting a vulnerability

Please open a private security advisory on this repository
(**Security > Report a vulnerability**) rather than a public issue. I aim to respond within
seven days.
