# Essential Eight assessment: RECEPTION-PC01

Evidence collected 2026-10-20T09:15:00 | e8checker 0.2.0

**Result: 0 of 8 strategies meet Maturity Level One.**

| Strategy | Verdict | Pass | Fail | Manual | Error |
| --- | --- | --- | --- | --- | --- |
| Application control | Maturity Level Zero | 0 | 2 | 0 | 0 |
| Patch applications | Maturity Level Zero | 0 | 1 | 3 | 0 |
| Configure Microsoft Office macro settings | Maturity Level Zero | 0 | 4 | 0 | 0 |
| User application hardening | Maturity Level Zero | 0 | 4 | 0 | 0 |
| Restrict administrative privileges | Maturity Level Zero | 0 | 2 | 3 | 0 |
| Patch operating systems | Maturity Level Zero | 0 | 3 | 0 | 0 |
| Multi-factor authentication | Unconfirmed (manual answers needed) | 0 | 0 | 4 | 0 |
| Regular backups | Unconfirmed (manual answers needed) | 0 | 0 | 4 | 0 |

## Remediation priorities

- **AC-01 Application control enforced for executables, scripts and installers** (High): Deploy AppLocker rules for Exe, Script and Msi in Enforce mode (and start the Application Identity service), or deploy an enforced WDAC / App Control for Business policy.
- **PA-01 No unsupported applications installed** (High): Remove the listed applications or replace them with vendor-supported versions.
- **OM-01 Macros disabled for users without an approved business requirement** (High): Set 'VBA Macro Notification Settings' to 'Disable all without notification' by Group Policy for Word, Excel and PowerPoint. Record approved exceptions separately.
- **OM-02 Macros in files from the internet are blocked** (High): Enable 'Block macros from running in Office files from the Internet' by Group Policy for Word, Excel and PowerPoint.
- **AH-01 Internet Explorer 11 is disabled or removed** (High): Disable the Internet-Explorer-Optional feature (Windows 10) and block IE mode in Edge unless a documented business need exists.
- **RA-01 Day-to-day user account is not a local administrator** (High): Remove the user from the local Administrators group and give administrators a separate privileged account for admin work only.
- **PO-01 Operating system is still supported by the vendor** (High): Upgrade to a supported Windows release, or document enrolment in Extended Security Updates.
- **PO-02 Operating system patches installed within one month** (High): Install outstanding Windows updates and confirm the update policy applies security updates within one month of release.
- **AC-02 Application control covers software libraries (DLLs)** (Medium): Enable the AppLocker DLL rule collection in Enforce mode after testing, or use WDAC, which covers libraries by default.
- **OM-03 Microsoft Office macro antivirus scanning is enabled** (Medium): Set 'Macro Runtime Scan Scope' to 'Enable for all documents' by Group Policy and keep Microsoft Defender (or another AMSI-aware antivirus) active.
- **OM-04 Users cannot change macro security settings** (Medium): Deliver all Office macro settings through Group Policy or Intune so users cannot override them in the Trust Center.
- **AH-02 Web browsers do not process web advertisements** (Medium): Force-install an ad blocker through the ExtensionInstallForcelist policy for each browser, or block advertising at a web proxy or DNS filter.
- **AH-03 Web browsers do not process Java from the internet** (Medium): Remove Internet Explorer 11 (the last browser able to run Java applets) or the Java browser plug-in.
- **AH-04 Users cannot change web browser security settings** (Medium): Manage each browser through Group Policy or Intune (ADMX templates for Edge and Chrome, policies.json or ADMX for Firefox).
- **RA-02 Local Administrators group membership is minimal** (Medium): Review every member of the local Administrators group; remove anyone without a validated need and manage the built-in account with Windows LAPS.
- **PO-03 Windows Update is not disabled** (Medium): Set the Windows Update service (wuauserv) to Manual or Automatic and remove any NoAutoUpdate policy, or confirm another patch tool (WSUS, Intune, SCCM) is in use.

## Application control

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| AC-01 | Application control enforced for executables, scripts and installers | **FAIL** | High | AppLocker not enforced: Script, Msi; audit only (logs but does not block): Exe. | PR.PS-05, ISO 8.19, ISO 8.7 |
| AC-02 | Application control covers software libraries (DLLs) | **FAIL** | Medium | The AppLocker DLL rule collection is in mode NotConfigured. | PR.PS-05, ISO 8.19 |

## Patch applications

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| PA-01 | No unsupported applications installed | **FAIL** | High | Unsupported software found: Adobe Flash Player 32 NPAPI - Adobe Flash Player (end of life 31 Dec 2020); Microsoft Office Professional Plus 2016 - Microsoft Office 2019 or earlier | PR.PS-02, ID.AM-02, ISO 8.8, ISO 8.19 |
| PA-02 | Automated asset discovery runs at least fortnightly | MANUAL | Medium | Not observable from the endpoint. Answer it in the answers file. | ID.AM-02, ISO 5.9 |
| PA-03 | Vulnerability scanner covers online services daily and office, browser, email, PDF and security software weekly | MANUAL | High | Not observable from the endpoint. Answer it in the answers file. | ID.RA-01, ISO 8.8 |
| PA-04 | Application patches applied within two weeks (48 hours for exploited internet-facing services) | MANUAL | High | Not observable from the endpoint. Answer it in the answers file. | PR.PS-02, ISO 8.8 |

## Configure Microsoft Office macro settings

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| OM-01 | Macros disabled for users without an approved business requirement | **FAIL** | High | Macros are not disabled by policy: Word=not set, Excel=not set, PowerPoint=not set. | PR.PS-01, ISO 8.9, ISO 8.7 |
| OM-02 | Macros in files from the internet are blocked | **FAIL** | High | Internet macro blocking is not enforced by policy: Word=not set, Excel=not set, PowerPoint=not set. | PR.PS-01, ISO 8.9, ISO 8.7 |
| OM-03 | Microsoft Office macro antivirus scanning is enabled | **FAIL** | Medium | MacroRuntimeScanScope is not set; expected 2. | PR.PS-01, ISO 8.9, ISO 8.7 |
| OM-04 | Users cannot change macro security settings | **FAIL** | Medium | No Office macro policy was found, so users can change these settings. | PR.PS-01, ISO 8.9, ISO 8.7 |

## User application hardening

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| AH-01 | Internet Explorer 11 is disabled or removed | **FAIL** | High | The Internet Explorer 11 optional feature is enabled. | PR.PS-01, ISO 8.9 |
| AH-02 | Web browsers do not process web advertisements | **FAIL** | Medium | No enforced ad blocker in: chrome, edge. | PR.PS-01, ISO 8.9 |
| AH-03 | Web browsers do not process Java from the internet | **FAIL** | Medium | Java is installed and Internet Explorer 11 can still load the Java plug-in. | PR.PS-01, ISO 8.9 |
| AH-04 | Users cannot change web browser security settings | **FAIL** | Medium | Not managed by policy: chrome, edge. | PR.PS-01, ISO 8.9 |

## Restrict administrative privileges

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| RA-01 | Day-to-day user account is not a local administrator | **FAIL** | High | RECEPTION-PC01\frontdesk is a member of the local Administrators group. | PR.AA-05, ISO 8.2, ISO 5.15 |
| RA-02 | Local Administrators group membership is minimal | **FAIL** | Medium | 3 enabled members (limit 2): RECEPTION-PC01\Administrator, RECEPTION-PC01\frontdesk, RECEPTION-PC01\itsupport. | PR.AA-05, ISO 8.2, ISO 5.15 |
| RA-03 | Requests for privileged access are validated when first requested | MANUAL | Medium | Not observable from the endpoint. Answer it in the answers file. | PR.AA-05, ISO 8.2, ISO 5.15 |
| RA-04 | Privileged accounts cannot access the internet, email or web services | MANUAL | High | Not observable from the endpoint. Answer it in the answers file. | PR.AA-05, ISO 8.2, ISO 5.15 |
| RA-05 | Privileged and unprivileged operating environments are separated | MANUAL | High | Not observable from the endpoint. Answer it in the answers file. | PR.AA-05, ISO 8.2, ISO 5.15 |

## Patch operating systems

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| PO-01 | Operating system is still supported by the vendor | **FAIL** | High | Windows 10 22H2 (Microsoft Windows 10 Pro) reached end of servicing on 14 Oct 2025. | PR.PS-02, ISO 8.8 |
| PO-02 | Operating system patches installed within one month | **FAIL** | High | Most recent update was installed 67 days ago (14 Aug 2026). | PR.PS-02, ID.RA-01, ISO 8.8 |
| PO-03 | Windows Update is not disabled | **FAIL** | Medium | Automatic patching is blocked: the wuauserv service is Disabled and the NoAutoUpdate policy is set. | PR.PS-02, ISO 8.8 |

## Multi-factor authentication

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| MF-01 | MFA is used to authenticate users to the organisation's online services that process, store or communicate sensitive data | MANUAL | High | Not observable from the endpoint. Answer it in the answers file. | PR.AA-03, ISO 8.5 |
| MF-02 | MFA is used to authenticate users to third-party online services that process, store or communicate the organisation's sensitive data | MANUAL | High | Not observable from the endpoint. Answer it in the answers file. | PR.AA-03, ISO 8.5 |
| MF-03 | MFA uses something users have and something they know or are | MANUAL | Medium | Not observable from the endpoint. Answer it in the answers file. | PR.AA-03, ISO 8.5 |
| MF-04 | MFA is used for customers accessing the organisation's online customer services | MANUAL | Medium | Not observable from the endpoint. Answer it in the answers file. | PR.AA-03, ISO 8.5 |

## Regular backups

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| BK-01 | Backups of data, applications and settings are performed and retained according to business criticality and continuity requirements | MANUAL | High | Not observable from the endpoint. Answer it in the answers file. | PR.DS-11, ISO 8.13 |
| BK-02 | Backups are synchronised to enable restoration to a common point in time and are retained in a secure and resilient manner | MANUAL | High | Not observable from the endpoint. Answer it in the answers file. | PR.DS-11, ISO 8.13 |
| BK-03 | Restoration from backup is tested as part of disaster recovery exercises | MANUAL | High | Not observable from the endpoint. Answer it in the answers file. | PR.DS-11, ISO 8.13 |
| BK-04 | Unprivileged accounts cannot access, modify or delete other accounts' backups or their own backups | MANUAL | High | Not observable from the endpoint. Answer it in the answers file. | PR.DS-11, ISO 8.13 |

## Supporting controls

These sit outside the Essential Eight and do not affect the verdict above.

| ID | Control | Status | Severity | Detail | Mappings |
| --- | --- | --- | --- | --- | --- |
| SC-01 | Microsoft Defender real-time protection is on | **FAIL** | High | Defender real-time protection is off and no other antivirus is registered. | DE.CM-09, ISO 8.7 |
| SC-02 | Antivirus signatures are less than a week old | **FAIL** | Medium | Signatures are 23 days old. | DE.CM-09, ISO 8.7 |
| SC-03 | Windows Firewall is on for every network profile | **FAIL** | High | Firewall is off for: Public. | PR.IR-01, ISO 8.20 |
| SC-04 | System drive is encrypted with BitLocker | **FAIL** | Medium | BitLocker protection status for the system drive is Off. | PR.DS-01, ISO 8.24 |

---
Framework mappings are indicative, not an official ASD, NIST or ISO crosswalk. Manual controls need assessor answers before the verdict is final.
