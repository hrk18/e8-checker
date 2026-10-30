# Control mapping

Generated from the check registry by `tools/generate_mapping_doc.py`. Do not edit by hand.

Every check maps to an ASD Essential Eight requirement (or a supporting control), a NIST
Cybersecurity Framework 2.0 subcategory and an ISO/IEC 27001:2022 Annex A control. Level 2 checks
run only with `--level 2` and are reported as readiness findings, not as an ML2 verdict.
The NIST and ISO mappings are indicative, not an official crosswalk.

## Application control

| ID | Level | Type | Control | Severity | NIST CSF 2.0 | ISO 27001:2022 |
| --- | --- | --- | --- | --- | --- | --- |
| AC-01 | 1 | Automated | Application control enforced for executables, scripts and installers | High | PR.PS-05 Installation and execution of unauthorized software are prevented | A.8.19 Installation of software on operational systems<br>A.8.7 Protection against malware |
| AC-02 | 1 | Automated | Application control covers software libraries (DLLs) | Medium | PR.PS-05 Installation and execution of unauthorized software are prevented | A.8.19 Installation of software on operational systems |

## Patch applications

| ID | Level | Type | Control | Severity | NIST CSF 2.0 | ISO 27001:2022 |
| --- | --- | --- | --- | --- | --- | --- |
| PA-01 | 1 | Automated | No unsupported applications installed | High | PR.PS-02 Software is maintained, replaced, and removed commensurate with risk<br>ID.AM-02 Inventories of software, services, and systems are maintained | A.8.8 Management of technical vulnerabilities<br>A.8.19 Installation of software on operational systems |
| PA-02 | 1 | Manual | Automated asset discovery runs at least fortnightly | Medium | ID.AM-02 Inventories of software, services, and systems are maintained | A.5.9 Inventory of information and other associated assets |
| PA-03 | 1 | Manual | Vulnerability scanner covers online services daily and office, browser, email, PDF and security software weekly | High | ID.RA-01 Vulnerabilities in assets are identified, validated, and recorded | A.8.8 Management of technical vulnerabilities |
| PA-04 | 1 | Manual | Application patches applied within two weeks (48 hours for exploited internet-facing services) | High | PR.PS-02 Software is maintained, replaced, and removed commensurate with risk | A.8.8 Management of technical vulnerabilities |

## Configure Microsoft Office macro settings

| ID | Level | Type | Control | Severity | NIST CSF 2.0 | ISO 27001:2022 |
| --- | --- | --- | --- | --- | --- | --- |
| OM-01 | 1 | Automated | Macros disabled for users without an approved business requirement | High | PR.PS-01 Configuration management practices are established and applied | A.8.9 Configuration management<br>A.8.7 Protection against malware |
| OM-02 | 1 | Automated | Macros in files from the internet are blocked | High | PR.PS-01 Configuration management practices are established and applied | A.8.9 Configuration management<br>A.8.7 Protection against malware |
| OM-03 | 1 | Automated | Microsoft Office macro antivirus scanning is enabled | Medium | PR.PS-01 Configuration management practices are established and applied | A.8.9 Configuration management<br>A.8.7 Protection against malware |
| OM-04 | 1 | Automated | Users cannot change macro security settings | Medium | PR.PS-01 Configuration management practices are established and applied | A.8.9 Configuration management<br>A.8.7 Protection against malware |
| OM-05 | 2 | Automated | Microsoft Office macros are blocked from making Win32 API calls | High | PR.PS-01 Configuration management practices are established and applied | A.8.9 Configuration management<br>A.8.7 Protection against malware |

## User application hardening

| ID | Level | Type | Control | Severity | NIST CSF 2.0 | ISO 27001:2022 |
| --- | --- | --- | --- | --- | --- | --- |
| AH-01 | 1 | Automated | Internet Explorer 11 is disabled or removed | High | PR.PS-01 Configuration management practices are established and applied | A.8.9 Configuration management |
| AH-02 | 1 | Automated | Web browsers do not process web advertisements | Medium | PR.PS-01 Configuration management practices are established and applied | A.8.9 Configuration management |
| AH-03 | 1 | Automated | Web browsers do not process Java from the internet | Medium | PR.PS-01 Configuration management practices are established and applied | A.8.9 Configuration management |
| AH-04 | 1 | Automated | Users cannot change web browser security settings | Medium | PR.PS-01 Configuration management practices are established and applied | A.8.9 Configuration management |
| AH-05 | 2 | Automated | Microsoft Office is blocked from creating child processes | High | PR.PS-01 Configuration management practices are established and applied | A.8.9 Configuration management<br>A.8.7 Protection against malware |
| AH-06 | 2 | Automated | Microsoft Office is blocked from injecting code into other processes | High | PR.PS-01 Configuration management practices are established and applied | A.8.9 Configuration management<br>A.8.7 Protection against malware |
| AH-07 | 2 | Automated | Microsoft Office is blocked from creating executable content | Medium | PR.PS-01 Configuration management practices are established and applied | A.8.9 Configuration management<br>A.8.7 Protection against malware |
| AH-08 | 2 | Automated | PowerShell module logging, script block logging and transcription are enabled | Medium | PR.PS-04 Log records are generated and made available for continuous monitoring<br>DE.CM-09 Computing hardware and software and their data are monitored for adverse events | A.8.15 Logging |
| AH-09 | 2 | Automated | Command line process creation events are captured | Medium | PR.PS-04 Log records are generated and made available for continuous monitoring<br>DE.CM-09 Computing hardware and software and their data are monitored for adverse events | A.8.15 Logging |
| AH-10 | 2 | Manual | Command line, PowerShell and other required events are centrally logged and protected from unauthorised modification and deletion | High | PR.PS-04 Log records are generated and made available for continuous monitoring<br>DE.CM-09 Computing hardware and software and their data are monitored for adverse events | A.8.15 Logging |

## Restrict administrative privileges

| ID | Level | Type | Control | Severity | NIST CSF 2.0 | ISO 27001:2022 |
| --- | --- | --- | --- | --- | --- | --- |
| RA-01 | 1 | Automated | Day-to-day user account is not a local administrator | High | PR.AA-05 Access permissions, entitlements, and authorizations are managed (least privilege) | A.8.2 Privileged access rights<br>A.5.15 Access control |
| RA-02 | 1 | Automated | Local Administrators group membership is minimal | Medium | PR.AA-05 Access permissions, entitlements, and authorizations are managed (least privilege) | A.8.2 Privileged access rights<br>A.5.15 Access control |
| RA-03 | 1 | Manual | Requests for privileged access are validated when first requested | Medium | PR.AA-05 Access permissions, entitlements, and authorizations are managed (least privilege) | A.8.2 Privileged access rights<br>A.5.15 Access control |
| RA-04 | 1 | Manual | Privileged accounts cannot access the internet, email or web services | High | PR.AA-05 Access permissions, entitlements, and authorizations are managed (least privilege) | A.8.2 Privileged access rights<br>A.5.15 Access control |
| RA-05 | 1 | Manual | Privileged and unprivileged operating environments are separated | High | PR.AA-05 Access permissions, entitlements, and authorizations are managed (least privilege) | A.8.2 Privileged access rights<br>A.5.15 Access control |
| RA-06 | 2 | Automated | Local administrator account credentials are long, unique, unpredictable and managed | High | PR.AA-01 Identities and credentials for authorized users, services, and hardware are managed by the organization | A.5.17 Authentication information<br>A.8.2 Privileged access rights |
| RA-07 | 2 | Manual | Privileged access to systems and applications is disabled after 12 months unless revalidated | Medium | PR.AA-05 Access permissions, entitlements, and authorizations are managed (least privilege) | A.8.2 Privileged access rights<br>A.5.18 Access rights |
| RA-08 | 2 | Manual | Privileged access to systems and applications is disabled after 45 days of inactivity | Medium | PR.AA-05 Access permissions, entitlements, and authorizations are managed (least privilege) | A.8.2 Privileged access rights<br>A.5.18 Access rights |
| RA-09 | 2 | Manual | Administrative activities are conducted through jump servers | Medium | PR.AA-05 Access permissions, entitlements, and authorizations are managed (least privilege) | A.8.2 Privileged access rights<br>A.5.18 Access rights |

## Patch operating systems

| ID | Level | Type | Control | Severity | NIST CSF 2.0 | ISO 27001:2022 |
| --- | --- | --- | --- | --- | --- | --- |
| PO-01 | 1 | Automated | Operating system is still supported by the vendor | High | PR.PS-02 Software is maintained, replaced, and removed commensurate with risk | A.8.8 Management of technical vulnerabilities |
| PO-02 | 1 | Automated | Operating system patches installed within one month | High | PR.PS-02 Software is maintained, replaced, and removed commensurate with risk<br>ID.RA-01 Vulnerabilities in assets are identified, validated, and recorded | A.8.8 Management of technical vulnerabilities |
| PO-03 | 1 | Automated | Windows Update is not disabled | Medium | PR.PS-02 Software is maintained, replaced, and removed commensurate with risk | A.8.8 Management of technical vulnerabilities |

## Multi-factor authentication

| ID | Level | Type | Control | Severity | NIST CSF 2.0 | ISO 27001:2022 |
| --- | --- | --- | --- | --- | --- | --- |
| MF-01 | 1 | Manual | MFA is used to authenticate users to the organisation's online services that process, store or communicate sensitive data | High | PR.AA-03 Users, services, and hardware are authenticated | A.8.5 Secure authentication |
| MF-02 | 1 | Manual | MFA is used to authenticate users to third-party online services that process, store or communicate the organisation's sensitive data | High | PR.AA-03 Users, services, and hardware are authenticated | A.8.5 Secure authentication |
| MF-03 | 1 | Manual | MFA uses something users have and something they know or are | Medium | PR.AA-03 Users, services, and hardware are authenticated | A.8.5 Secure authentication |
| MF-04 | 1 | Manual | MFA is used for customers accessing the organisation's online customer services | Medium | PR.AA-03 Users, services, and hardware are authenticated | A.8.5 Secure authentication |

## Regular backups

| ID | Level | Type | Control | Severity | NIST CSF 2.0 | ISO 27001:2022 |
| --- | --- | --- | --- | --- | --- | --- |
| BK-01 | 1 | Manual | Backups of data, applications and settings are performed and retained according to business criticality and continuity requirements | High | PR.DS-11 Backups of data are created, protected, maintained, and tested | A.8.13 Information backup |
| BK-02 | 1 | Manual | Backups are synchronised to enable restoration to a common point in time and are retained in a secure and resilient manner | High | PR.DS-11 Backups of data are created, protected, maintained, and tested | A.8.13 Information backup |
| BK-03 | 1 | Manual | Restoration from backup is tested as part of disaster recovery exercises | High | PR.DS-11 Backups of data are created, protected, maintained, and tested | A.8.13 Information backup |
| BK-04 | 1 | Manual | Unprivileged accounts cannot access, modify or delete other accounts' backups or their own backups | High | PR.DS-11 Backups of data are created, protected, maintained, and tested | A.8.13 Information backup |

## Supporting controls (outside the Essential Eight)

| ID | Level | Type | Control | Severity | NIST CSF 2.0 | ISO 27001:2022 |
| --- | --- | --- | --- | --- | --- | --- |
| SC-01 | 1 | Automated | Microsoft Defender real-time protection is on | High | DE.CM-09 Computing hardware and software and their data are monitored for adverse events | A.8.7 Protection against malware |
| SC-02 | 1 | Automated | Antivirus signatures are less than a week old | Medium | DE.CM-09 Computing hardware and software and their data are monitored for adverse events | A.8.7 Protection against malware |
| SC-03 | 1 | Automated | Windows Firewall is on for every network profile | High | PR.IR-01 Networks and environments are protected from unauthorized logical access and usage | A.8.20 Networks security |
| SC-04 | 1 | Automated | System drive is encrypted with BitLocker | Medium | PR.DS-01 The confidentiality, integrity, and availability of data-at-rest are protected | A.8.24 Use of cryptography |
| SC-05 | 2 | Automated | LSA protection is enabled (an ML3 requirement) | Medium | PR.AA-01 Identities and credentials for authorized users, services, and hardware are managed by the organization | A.5.17 Authentication information |
| SC-06 | 2 | Automated | Credential Guard is running (an ML3 requirement) | Medium | PR.AA-01 Identities and credentials for authorized users, services, and hardware are managed by the organization | A.5.17 Authentication information |
