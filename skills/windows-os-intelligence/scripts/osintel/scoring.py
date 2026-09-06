from __future__ import annotations

import re
from typing import Iterable, List, Sequence


COMPONENT_RULES = {
    "RDP": ("remote desktop", "rdp", "mstsc", "remoteapp"),
    "RDS": ("remote desktop services", "rdsh", "rd gateway", "terminal services"),
    "Hyper-V": ("hyper-v", "hypervisor", "vmwp", "vmswitch", "nested virtualization"),
    "VBS": ("virtualization-based security", "vbs", "hvci", "memory integrity"),
    "Credential Guard": ("credential guard",),
    "GPU/display": ("gpu", "graphics", "display", "wddm", "dwm", "directx", "black screen"),
    "FSLogix/profile": ("fslogix", "profile container", "vhdx", "cloud cache", "user profile"),
    "authentication": ("logon", "sign-in", "signin", "lsass", "kerberos", "credssp", "nla", "windows hello"),
    "networking": ("network", "tcp", "udp", "vpn", "dns", "smb", "rpc", "disconnect"),
    "printing": ("print", "printer", "spooler"),
    "peripheral redirection": ("usb", "smart card", "camera", "audio redirection", "device redirection"),
    "Windows Update": ("windows update", "cumulative update", "quality update", "servicing stack", "oob", "known issue rollback"),
    "image/recovery": ("sysprep", "image", "reset this pc", "recovery", "upgrade", "rollback", "boot"),
}


def infer_components(text: str) -> List[str]:
    lowered = text.casefold()
    return sorted(name for name, terms in COMPONENT_RULES.items() if any(term in lowered for term in terms))


def infer_roles(products: Sequence[str], components: Sequence[str]) -> List[str]:
    roles = set()
    joined_products = " ".join(products).casefold()
    component_set = set(components)
    if "windows 10" in joined_products or "windows 11" in joined_products:
        roles.add("guest")
    if "windows server" in joined_products:
        roles.update({"guest", "host"})
    if "Hyper-V" in component_set or "VBS" in component_set:
        roles.add("host")
    if "RDP" in component_set or "RDS" in component_set:
        roles.update({"guest", "host"})
    if "FSLogix/profile" in component_set:
        roles.update({"guest", "profile/file service"})
    if "authentication" in component_set:
        roles.update({"guest", "directory"})
    return sorted(roles or {"unknown"})


def risk_score(
    text: str,
    products: Sequence[str],
    components: Sequence[str],
    cvss: float = 0.0,
    exploited: bool = False,
    preview: bool = False,
) -> int:
    lowered = text.casefold()
    score = 25 if products else 0
    score += 25 if components else 5
    if cvss >= 9.0:
        score += 20
    elif cvss >= 7.0:
        score += 16
    elif cvss >= 4.0:
        score += 10
    elif any(term in lowered for term in ("data loss", "blue screen", "bugcheck", "black screen", "fails to boot", "fail to launch", "unresponsive")):
        score += 18
    else:
        score += 6
    if exploited:
        score += 20
    elif any(term in lowered for term in ("out-of-band", "oob", "emergency", "known issue rollback", "safeguard hold")):
        score += 14
    elif any(term in lowered for term in ("critical", "remote code execution", "elevation of privilege")):
        score += 10
    else:
        score += 4
    families = {"server" if "server" in item.casefold() else "client" for item in products}
    score += 10 if len(families) > 1 or len(products) >= 3 else 5
    if preview:
        score = min(score, 70)
    return min(score, 100)


def extract_identifiers(text: str):
    return {
        "cve": sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.I))),
        "kb": sorted(set(value.upper() for value in re.findall(r"KB\d{6,8}", text, flags=re.I))),
        "build": sorted(set(re.findall(r"\b(?:OS\s+Build\s+)?\d{5}\.\d{2,6}\b", text, flags=re.I))),
        "safeguard_hold": sorted(set(re.findall(r"\bsafeguard(?: hold)? ID\s*(\d+)\b", text, flags=re.I))),
    }

