# Essential Eight fleet summary

**0 of 3 hosts meet Maturity Level One across all eight strategies.**

## Strategy coverage

| Strategy | Hosts at ML1 | Coverage |
| --- | --- | --- |
| Application control | 1 / 3 | 33% |
| Patch applications | 2 / 3 | 67% |
| Configure Microsoft Office macro settings | 1 / 3 | 33% |
| User application hardening | 1 / 3 | 33% |
| Restrict administrative privileges | 0 / 3 | 0% |
| Patch operating systems | 1 / 3 | 33% |
| Multi-factor authentication | 3 / 3 | 100% |
| Regular backups | 3 / 3 | 100% |

## Fixes that would help the most hosts

| Check | Control | Severity | Hosts failing | Hosts |
| --- | --- | --- | --- | --- |
| RA-05 | Privileged and unprivileged operating environments are separated | High | 3 | FIN-LT-042, LIB-PC07, RECEPTION-PC01 |
| PO-02 | Operating system patches installed within one month | High | 2 | LIB-PC07, RECEPTION-PC01 |
| AC-02 | Application control covers software libraries (DLLs) | Medium | 2 | LIB-PC07, RECEPTION-PC01 |
| AH-02 | Web browsers do not process web advertisements | Medium | 2 | LIB-PC07, RECEPTION-PC01 |
| AH-04 | Users cannot change web browser security settings | Medium | 2 | LIB-PC07, RECEPTION-PC01 |
| OM-03 | Microsoft Office macro antivirus scanning is enabled | Medium | 2 | LIB-PC07, RECEPTION-PC01 |
| RA-02 | Local Administrators group membership is minimal | Medium | 2 | LIB-PC07, RECEPTION-PC01 |
| AC-01 | Application control enforced for executables, scripts and installers | High | 1 | RECEPTION-PC01 |
| AH-01 | Internet Explorer 11 is disabled or removed | High | 1 | RECEPTION-PC01 |
| OM-01 | Macros disabled for users without an approved business requirement | High | 1 | RECEPTION-PC01 |

## Hosts (weakest first)

| Host | Collected | App control | Patch apps | Office macros | App hardening | Restrict admin | Patch OS | MFA | Backups | Total |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RECEPTION-PC01 | 2026-10-20T09:15:00 | - | - | - | - | - | - | ML1 | ML1 | 2/8 |
| LIB-PC07 | 2026-10-21T14:05:00 | - | ML1 | - | - | - | - | ML1 | ML1 | 3/8 |
| FIN-LT-042 | 2026-10-20T10:40:00 | ML1 | ML1 | ML1 | ML1 | - | ML1 | ML1 | ML1 | 7/8 |

---
A strategy counts only when every check passes; manual controls need assessor answers. Framework mappings are indicative, not an official ASD, NIST or ISO crosswalk.
