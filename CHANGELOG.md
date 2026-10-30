# Changelog

All notable changes to e8checker. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [semantic versioning](https://semver.org/).

## 0.2.0 - 2026-10-30

### Added

- **Maturity Level Two readiness** (`e8checker assess --level 2`). Checks for the ML2 requirements an
  endpoint can evidence: Office macros blocked from Win32 API calls; Office blocked from creating child
  processes, injecting code and creating executable content (Defender ASR rules in Block mode);
  PowerShell module, script block and transcription logging; command line process creation capture;
  local administrator credentials managed by LAPS. Organisational ML2 items (central protected
  logging, 12-month revalidation, 45-day inactivity, jump servers) are manual controls. Results appear
  in a separate "Level Two readiness" section and never change the ML1 verdict.
- LSA protection and Credential Guard, reported as Maturity Level Three items (not scored).
- Collector 0.2.0 writes evidence schema 2 with an `ml2` section. Schema 1 evidence is still read;
  Level Two checks on it report "re-run the 0.2.0 collector".
- `e8checker fleet`: assess a folder of evidence files and summarise hosts at ML1, coverage per
  strategy and the fixes that would help the most hosts, as Markdown, HTML or CSV. CSV output is
  protected against spreadsheet formula injection.
- `e8checker compare`: diff two JSON reports for the same host (fixed, regressed, still open), with
  `--fail-on-regression` for pipelines.
- `e8checker questionnaire`: answer the manual controls interactively (or from piped input) and write
  `answers.json`, with `--update` to revise and `--level 2` for the Level Two manual controls.
- A third, partially hardened sample host and sample fleet and Level Two reports.
- `docs/how-it-works.md`, a walkthrough of the design.
- The control mapping doc has a Level column.

### Fixed

- A manual control answered "no" now carries its remediation advice into the report.

## 0.1.0 - 2026-10-27

### Added

- First release: read-only PowerShell evidence collector, 30 Maturity Level One checks across the eight
  strategies plus four supporting controls, manual answers for organisational controls, Markdown, HTML
  and JSON reports, NIST CSF 2.0 and ISO/IEC 27001:2022 mappings, and `--fail-under` for pipelines.
