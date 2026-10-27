"""Indicative mappings from each check to NIST CSF 2.0 and ISO/IEC 27001:2022 Annex A.

These are the author's mappings to help a reader connect an Essential Eight finding to the
frameworks their organisation already reports against. They are not an official ASD,
NIST or ISO crosswalk.
"""

NIST_CSF_2 = {
    "ID.AM-02": "Inventories of software, services, and systems are maintained",
    "ID.RA-01": "Vulnerabilities in assets are identified, validated, and recorded",
    "PR.AA-03": "Users, services, and hardware are authenticated",
    "PR.AA-05": "Access permissions, entitlements, and authorizations are managed (least privilege)",
    "PR.DS-01": "The confidentiality, integrity, and availability of data-at-rest are protected",
    "PR.DS-11": "Backups of data are created, protected, maintained, and tested",
    "PR.IR-01": "Networks and environments are protected from unauthorized logical access and usage",
    "PR.PS-01": "Configuration management practices are established and applied",
    "PR.PS-02": "Software is maintained, replaced, and removed commensurate with risk",
    "PR.PS-05": "Installation and execution of unauthorized software are prevented",
    "DE.CM-09": "Computing hardware and software and their data are monitored for adverse events",
}

ISO_27001_2022 = {
    "5.9": "Inventory of information and other associated assets",
    "5.15": "Access control",
    "8.2": "Privileged access rights",
    "8.5": "Secure authentication",
    "8.7": "Protection against malware",
    "8.8": "Management of technical vulnerabilities",
    "8.9": "Configuration management",
    "8.13": "Information backup",
    "8.19": "Installation of software on operational systems",
    "8.20": "Networks security",
    "8.24": "Use of cryptography",
}


def describe_nist(code: str) -> str:
    return NIST_CSF_2.get(code, "")


def describe_iso(code: str) -> str:
    return ISO_27001_2022.get(code, "")
