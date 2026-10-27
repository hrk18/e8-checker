# Essential Eight assessment: FIN-LT-042

Evidence collected 2026-10-20T10:40:00 | e8checker 0.1.0

**Result: 7 of 8 strategies meet Maturity Level One.**

| Strategy | Verdict | Pass | Fail | Manual | Error |
| --- | --- | --- | --- | --- | --- |
| Application control | Maturity Level One | 2 | 0 | 0 | 0 |
| Patch applications | Maturity Level One | 4 | 0 | 0 | 0 |
| Configure Microsoft Office macro settings | Maturity Level One | 4 | 0 | 0 | 0 |
| User application hardening | Maturity Level One | 4 | 0 | 0 | 0 |
| Restrict administrative privileges | Maturity Level Zero | 4 | 1 | 0 | 0 |
| Patch operating systems | Maturity Level One | 3 | 0 | 0 | 0 |
| Multi-factor authentication | Maturity Level One | 4 | 0 | 0 | 0 |
| Regular backups | Maturity Level One | 4 | 0 | 0 | 0 |

## Remediation priorities

- **RA-05 Privileged and unprivileged operating environments are separated** (High): Use privileged access workstations or jump hosts, and deny unprivileged accounts logon to privileged environments (and the reverse).

## Application control

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| AC-01 | Application control enforced for executables, scripts and installers | PASS | High | AppLocker enforces Exe, Script and Msi rules and AppIDSvc is running. | PR.PS-05, ISO 8.19, ISO 8.7 |
| AC-02 | Application control covers software libraries (DLLs) | PASS | Medium | AppLocker DLL rules are enforced (9 rules). | PR.PS-05, ISO 8.19 |

## Patch applications

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| PA-01 | No unsupported applications installed | PASS | High | None of 3 installed applications match the unsupported list. | PR.PS-02, ID.AM-02, ISO 8.8, ISO 8.19 |
| PA-02 | Automated asset discovery runs at least fortnightly | PASS | Medium | Confirmed implemented by the assessor. Evidence: Intune device inventory refreshes daily | ID.AM-02, ISO 5.9 |
| PA-03 | Vulnerability scanner covers online services daily and office, browser, email, PDF and security software weekly | PASS | High | Confirmed implemented by the assessor. Evidence: Tenable Nessus: daily external scan, weekly authenticated workstation scan | ID.RA-01, ISO 8.8 |
| PA-04 | Application patches applied within two weeks (48 hours for exploited internet-facing services) | PASS | High | Confirmed implemented by the assessor. Evidence: Patch SLA report for September shows 96% within 14 days | PR.PS-02, ISO 8.8 |

## Configure Microsoft Office macro settings

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| OM-01 | Macros disabled for users without an approved business requirement | PASS | High | Macros are disabled by policy for Word, Excel, PowerPoint. | PR.PS-01, ISO 8.9, ISO 8.7 |
| OM-02 | Macros in files from the internet are blocked | PASS | High | Macros in files from the internet are blocked by policy. | PR.PS-01, ISO 8.9, ISO 8.7 |
| OM-03 | Microsoft Office macro antivirus scanning is enabled | PASS | Medium | Macro runtime scanning is enabled for all documents. | PR.PS-01, ISO 8.9, ISO 8.7 |
| OM-04 | Users cannot change macro security settings | PASS | Medium | Macro settings are delivered through the Office policy registry hive. | PR.PS-01, ISO 8.9, ISO 8.7 |

## User application hardening

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| AH-01 | Internet Explorer 11 is disabled or removed | PASS | High | Internet Explorer 11 is disabled or not present. | PR.PS-01, ISO 8.9 |
| AH-02 | Web browsers do not process web advertisements | PASS | Medium | Every installed browser has an enforced ad blocker. | PR.PS-01, ISO 8.9 |
| AH-03 | Web browsers do not process Java from the internet | PASS | Medium | No installed browser can load the Java browser plug-in. | PR.PS-01, ISO 8.9 |
| AH-04 | Users cannot change web browser security settings | PASS | Medium | All installed browsers are managed by policy: edge. | PR.PS-01, ISO 8.9 |

## Restrict administrative privileges

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| RA-01 | Day-to-day user account is not a local administrator | PASS | High | CORP\j.citizen is a standard (unprivileged) user. | PR.AA-05, ISO 8.2, ISO 5.15 |
| RA-02 | Local Administrators group membership is minimal | PASS | Medium | 2 enabled members: FIN-LT-042\Administrator, CORP\Workstation Admins. | PR.AA-05, ISO 8.2, ISO 5.15 |
| RA-03 | Requests for privileged access are validated when first requested | PASS | Medium | Confirmed implemented by the assessor. Evidence: Privileged access requests go through ServiceNow with manager approval | PR.AA-05, ISO 8.2, ISO 5.15 |
| RA-04 | Privileged accounts cannot access the internet, email or web services | PASS | High | Confirmed implemented by the assessor. Evidence: Proxy blocks the 'Tier 0/1 Admins' group; admin accounts have no mailbox | PR.AA-05, ISO 8.2, ISO 5.15 |
| RA-05 | Privileged and unprivileged operating environments are separated | **FAIL** | High | Assessor recorded this control as not implemented. Evidence: Admins use their normal laptop with RunAs; PAW rollout planned for Q1 | PR.AA-05, ISO 8.2, ISO 5.15 |

## Patch operating systems

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| PO-01 | Operating system is still supported by the vendor | PASS | High | Windows 11 24H2 (Microsoft Windows 11 Enterprise) is serviced until 12 Oct 2027. | PR.PS-02, ISO 8.8 |
| PO-02 | Operating system patches installed within one month | PASS | High | Most recent update was installed 5 days ago (15 Oct 2026). | PR.PS-02, ID.RA-01, ISO 8.8 |
| PO-03 | Windows Update is not disabled | PASS | Medium | Windows Update service start type is Manual. | PR.PS-02, ISO 8.8 |

## Multi-factor authentication

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| MF-01 | MFA is used to authenticate users to the organisation's online services that process, store or communicate sensitive data | PASS | High | Confirmed implemented by the assessor. Evidence: Entra Conditional Access policy 'Require MFA - all users' | PR.AA-03, ISO 8.5 |
| MF-02 | MFA is used to authenticate users to third-party online services that process, store or communicate the organisation's sensitive data | PASS | High | Confirmed implemented by the assessor. Evidence: SaaS register shows SSO + MFA for all services holding council data | PR.AA-03, ISO 8.5 |
| MF-03 | MFA uses something users have and something they know or are | PASS | Medium | Confirmed implemented by the assessor. Evidence: Microsoft Authenticator number matching; SMS disabled | PR.AA-03, ISO 8.5 |
| MF-04 | MFA is used for customers accessing the organisation's online customer services | PASS | Medium | Confirmed implemented by the assessor. Evidence: Customer portal offers and defaults to app-based MFA | PR.AA-03, ISO 8.5 |

## Regular backups

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| BK-01 | Backups of data, applications and settings are performed and retained according to business criticality and continuity requirements | PASS | High | Confirmed implemented by the assessor. Evidence: Backup schedule documented per system in the BCP | PR.DS-11, ISO 8.13 |
| BK-02 | Backups are synchronised to enable restoration to a common point in time and are retained in a secure and resilient manner | PASS | High | Confirmed implemented by the assessor. Evidence: Veeam with immutable object storage, 30-day retention | PR.DS-11, ISO 8.13 |
| BK-03 | Restoration from backup is tested as part of disaster recovery exercises | PASS | High | Confirmed implemented by the assessor. Evidence: Restore test recorded in the June 2026 DR exercise | PR.DS-11, ISO 8.13 |
| BK-04 | Unprivileged accounts cannot access, modify or delete other accounts' backups or their own backups | PASS | High | Confirmed implemented by the assessor. Evidence: Backup console limited to the Backup Admins group | PR.DS-11, ISO 8.13 |

## Supporting controls

These sit outside the Essential Eight and do not affect the verdict above.

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| SC-01 | Microsoft Defender real-time protection is on | PASS | High | Defender antivirus and real-time protection are on. | DE.CM-09, ISO 8.7 |
| SC-02 | Antivirus signatures are less than a week old | PASS | Medium | Signatures are 0 day(s) old. | DE.CM-09, ISO 8.7 |
| SC-03 | Windows Firewall is on for every network profile | PASS | High | Firewall is on for all profiles. | PR.IR-01, ISO 8.20 |
| SC-04 | System drive is encrypted with BitLocker | PASS | Medium | BitLocker protection is on for the system drive. | PR.DS-01, ISO 8.24 |

---
Framework mappings are indicative, not an official ASD, NIST or ISO crosswalk. Manual controls need assessor answers before the verdict is final.
