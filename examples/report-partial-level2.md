# Essential Eight assessment: LIB-PC07

Evidence collected 2026-10-21T14:05:00 | e8checker 0.2.0

**Result: 3 of 8 strategies meet Maturity Level One.**

| Strategy | Verdict | Pass | Fail | Manual | Error |
| --- | --- | --- | --- | --- | --- |
| Application control | Maturity Level Zero | 1 | 1 | 0 | 0 |
| Patch applications | Maturity Level One | 4 | 0 | 0 | 0 |
| Configure Microsoft Office macro settings | Maturity Level Zero | 3 | 1 | 0 | 0 |
| User application hardening | Maturity Level Zero | 2 | 2 | 0 | 0 |
| Restrict administrative privileges | Maturity Level Zero | 3 | 2 | 0 | 0 |
| Patch operating systems | Maturity Level Zero | 2 | 1 | 0 | 0 |
| Multi-factor authentication | Maturity Level One | 4 | 0 | 0 | 0 |
| Regular backups | Maturity Level One | 4 | 0 | 0 | 0 |

## Remediation priorities

- **RA-05 Privileged and unprivileged operating environments are separated** (High): Use privileged access workstations or jump hosts, and deny unprivileged accounts logon to privileged environments (and the reverse).
- **PO-02 Operating system patches installed within one month** (High): Install outstanding Windows updates and confirm the update policy applies security updates within one month of release.
- **AC-02 Application control covers software libraries (DLLs)** (Medium): Enable the AppLocker DLL rule collection in Enforce mode after testing, or use WDAC, which covers libraries by default.
- **OM-03 Microsoft Office macro antivirus scanning is enabled** (Medium): Set 'Macro Runtime Scan Scope' to 'Enable for all documents' by Group Policy and keep Microsoft Defender (or another AMSI-aware antivirus) active.
- **AH-02 Web browsers do not process web advertisements** (Medium): Force-install an ad blocker through the ExtensionInstallForcelist policy for each browser, or block advertising at a web proxy or DNS filter.
- **AH-04 Users cannot change web browser security settings** (Medium): Manage each browser through Group Policy or Intune (ADMX templates for Edge and Chrome, policies.json or ADMX for Firefox).
- **RA-02 Local Administrators group membership is minimal** (Medium): Review every member of the local Administrators group; remove anyone without a validated need and manage the built-in account with Windows LAPS.

## Application control

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| AC-01 | Application control enforced for executables, scripts and installers | PASS | High | AppLocker enforces Exe, Script and Msi rules and AppIDSvc is running. | PR.PS-05, ISO 8.19, ISO 8.7 |
| AC-02 | Application control covers software libraries (DLLs) | **FAIL** | Medium | The AppLocker DLL rule collection is in mode NotConfigured. | PR.PS-05, ISO 8.19 |

## Patch applications

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| PA-01 | No unsupported applications installed | PASS | High | None of 4 installed applications match the unsupported list. | PR.PS-02, ID.AM-02, ISO 8.8, ISO 8.19 |
| PA-02 | Automated asset discovery runs at least fortnightly | PASS | Medium | Confirmed implemented by the assessor. Evidence: Intune device inventory refreshes daily | ID.AM-02, ISO 5.9 |
| PA-03 | Vulnerability scanner covers online services daily and office, browser, email, PDF and security software weekly | PASS | High | Confirmed implemented by the assessor. Evidence: Tenable Nessus: daily external scan, weekly authenticated workstation scan | ID.RA-01, ISO 8.8 |
| PA-04 | Application patches applied within two weeks (48 hours for exploited internet-facing services) | PASS | High | Confirmed implemented by the assessor. Evidence: Patch SLA report for September shows 96% within 14 days | PR.PS-02, ISO 8.8 |

## Configure Microsoft Office macro settings

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| OM-01 | Macros disabled for users without an approved business requirement | PASS | High | Macros are disabled by policy for Word, Excel, PowerPoint. | PR.PS-01, ISO 8.9, ISO 8.7 |
| OM-02 | Macros in files from the internet are blocked | PASS | High | Macros in files from the internet are blocked by policy. | PR.PS-01, ISO 8.9, ISO 8.7 |
| OM-03 | Microsoft Office macro antivirus scanning is enabled | **FAIL** | Medium | MacroRuntimeScanScope is not set; expected 2. | PR.PS-01, ISO 8.9, ISO 8.7 |
| OM-04 | Users cannot change macro security settings | PASS | Medium | Macro settings are delivered through the Office policy registry hive. | PR.PS-01, ISO 8.9, ISO 8.7 |

## User application hardening

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| AH-01 | Internet Explorer 11 is disabled or removed | PASS | High | Internet Explorer 11 is disabled or not present. | PR.PS-01, ISO 8.9 |
| AH-02 | Web browsers do not process web advertisements | **FAIL** | Medium | No enforced ad blocker in: firefox. | PR.PS-01, ISO 8.9 |
| AH-03 | Web browsers do not process Java from the internet | PASS | Medium | No installed browser can load the Java browser plug-in. | PR.PS-01, ISO 8.9 |
| AH-04 | Users cannot change web browser security settings | **FAIL** | Medium | Not managed by policy: firefox. | PR.PS-01, ISO 8.9 |

## Restrict administrative privileges

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| RA-01 | Day-to-day user account is not a local administrator | PASS | High | CORP\library.staff is a standard (unprivileged) user. | PR.AA-05, ISO 8.2, ISO 5.15 |
| RA-02 | Local Administrators group membership is minimal | **FAIL** | Medium | 3 enabled members (limit 2): LIB-PC07\Administrator, CORP\Workstation Admins, CORP\Library Supervisors. | PR.AA-05, ISO 8.2, ISO 5.15 |
| RA-03 | Requests for privileged access are validated when first requested | PASS | Medium | Confirmed implemented by the assessor. Evidence: Privileged access requests go through ServiceNow with manager approval | PR.AA-05, ISO 8.2, ISO 5.15 |
| RA-04 | Privileged accounts cannot access the internet, email or web services | PASS | High | Confirmed implemented by the assessor. Evidence: Proxy blocks the 'Tier 0/1 Admins' group; admin accounts have no mailbox | PR.AA-05, ISO 8.2, ISO 5.15 |
| RA-05 | Privileged and unprivileged operating environments are separated | **FAIL** | High | Assessor recorded this control as not implemented. Evidence: Admins use their normal laptop with RunAs; PAW rollout planned for Q1 | PR.AA-05, ISO 8.2, ISO 5.15 |

## Patch operating systems

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| PO-01 | Operating system is still supported by the vendor | PASS | High | Windows 11 24H2 (Microsoft Windows 11 Enterprise) is serviced until 12 Oct 2027. | PR.PS-02, ISO 8.8 |
| PO-02 | Operating system patches installed within one month | **FAIL** | High | Most recent update was installed 42 days ago (09 Sep 2026). | PR.PS-02, ID.RA-01, ISO 8.8 |
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

## Level Two readiness

These checks cover the Maturity Level Two requirements that one endpoint can evidence. They are not an ML2 verdict: ML2 also needs central logging, event analysis and process controls that this report cannot see, and every Level One requirement must be met first.

**3 passed, 4 failed, 4 need an assessor's answer.**

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| OM-05 | Microsoft Office macros are blocked from making Win32 API calls | PASS | High | The ASR rule that blocks Win32 API calls from Office macros is in Block mode. | PR.PS-01, ISO 8.9, ISO 8.7 |
| AH-05 | Microsoft Office is blocked from creating child processes | **FAIL** | High | The ASR rule that blocks Office applications creating child processes is set to Audit, not Block. | PR.PS-01, ISO 8.9, ISO 8.7 |
| AH-06 | Microsoft Office is blocked from injecting code into other processes | PASS | High | The ASR rule that blocks Office applications injecting code into other processes is in Block mode. | PR.PS-01, ISO 8.9, ISO 8.7 |
| AH-07 | Microsoft Office is blocked from creating executable content | **FAIL** | Medium | The ASR rule that blocks Office applications creating executable content (3b576869-a4ec-4529-8536-b80a7769e899) is not configured. | PR.PS-01, ISO 8.9, ISO 8.7 |
| AH-08 | PowerShell module logging, script block logging and transcription are enabled | **FAIL** | Medium | Not enabled by policy: module logging, transcription. | PR.PS-04, DE.CM-09, ISO 8.15 |
| AH-09 | Command line process creation events are captured | **FAIL** | Medium | Command lines are not included in event 4688. | PR.PS-04, DE.CM-09, ISO 8.15 |
| AH-10 | Command line, PowerShell and other required events are centrally logged and protected from unauthorised modification and deletion | MANUAL | High | Not observable from the endpoint. Answer it in the answers file. | PR.PS-04, DE.CM-09, ISO 8.15 |
| RA-06 | Local administrator account credentials are long, unique, unpredictable and managed | PASS | High | Windows LAPS backs up the local administrator password to Active Directory. | PR.AA-01, ISO 5.17, ISO 8.2 |
| RA-07 | Privileged access to systems and applications is disabled after 12 months unless revalidated | MANUAL | Medium | Not observable from the endpoint. Answer it in the answers file. | PR.AA-05, ISO 8.2, ISO 5.18 |
| RA-08 | Privileged access to systems and applications is disabled after 45 days of inactivity | MANUAL | Medium | Not observable from the endpoint. Answer it in the answers file. | PR.AA-05, ISO 8.2, ISO 5.18 |
| RA-09 | Administrative activities are conducted through jump servers | MANUAL | Medium | Not observable from the endpoint. Answer it in the answers file. | PR.AA-05, ISO 8.2, ISO 5.18 |

### Level Two fixes

- **AH-05 Microsoft Office is blocked from creating child processes** (High): Set the Defender ASR rule 'Block all Office applications from creating child processes' (d4f940ab-401b-4efc-aadc-ad5f3c50688a) to Block.
- **AH-07 Microsoft Office is blocked from creating executable content** (Medium): Set the Defender ASR rule 'Block Office applications from creating executable content' (3b576869-a4ec-4529-8536-b80a7769e899) to Block.
- **AH-08 PowerShell module logging, script block logging and transcription are enabled** (Medium): Enable 'Turn on Module Logging', 'Turn on PowerShell Script Block Logging' and 'Turn on PowerShell Transcription' under Administrative Templates > Windows Components > Windows PowerShell.
- **AH-09 Command line process creation events are captured** (Medium): Enable 'Audit Process Creation' (Success) and 'Include command line in process creation events' by Group Policy so event 4688 records the full command line.

### Maturity Level Three items (not scored)

Collected alongside the Level Two evidence because they protect the same credentials.

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| SC-05 | LSA protection is enabled (an ML3 requirement) | **FAIL** | Medium | LSA protection (RunAsPPL) is not enabled. | PR.AA-01, ISO 5.17 |
| SC-06 | Credential Guard is running (an ML3 requirement) | **FAIL** | Medium | Credential Guard is not running. | PR.AA-01, ISO 5.17 |

## Supporting controls

These sit outside the Essential Eight and do not affect the verdict above.

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| SC-01 | Microsoft Defender real-time protection is on | PASS | High | Defender antivirus and real-time protection are on. | DE.CM-09, ISO 8.7 |
| SC-02 | Antivirus signatures are less than a week old | PASS | Medium | Signatures are 1 day(s) old. | DE.CM-09, ISO 8.7 |
| SC-03 | Windows Firewall is on for every network profile | PASS | High | Firewall is on for all profiles. | PR.IR-01, ISO 8.20 |
| SC-04 | System drive is encrypted with BitLocker | PASS | Medium | BitLocker protection is on for the system drive. | PR.DS-01, ISO 8.24 |

---
Framework mappings are indicative, not an official ASD, NIST or ISO crosswalk. Manual controls need assessor answers before the verdict is final.
