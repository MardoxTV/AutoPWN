from __future__ import annotations
import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger("autopwn.hosts")

HOSTS_FILE = Path("/etc/hosts")
AUTOPWN_MARKER = "# autopwn"


def is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False  # not POSIX (Windows) — hosts file management not supported


def add_hosts(target_ip: str, hostnames: list[str], job_id: str) -> list[str]:
    """Append `<ip> <hostname>  # autopwn job=<job_id>` entries to /etc/hosts.
    Returns the hostnames that were actually written (skips duplicates)."""
    if not hostnames or not is_root() or not HOSTS_FILE.exists():
        return []
    try:
        existing = HOSTS_FILE.read_text()
    except Exception as e:
        logger.warning("Could not read /etc/hosts: %s", e)
        return []

    added: list[str] = []
    lines_to_add: list[str] = []
    for host in hostnames:
        # Skip if an exact ip+hostname pair already exists (autopwn-managed or not)
        if any(host in l.split() and target_ip in l.split() for l in existing.splitlines()):
            continue
        lines_to_add.append(f"{target_ip} {host}  {AUTOPWN_MARKER} job={job_id}")
        added.append(host)

    if not lines_to_add:
        return []

    try:
        with HOSTS_FILE.open("a") as f:
            f.write("\n" + "\n".join(lines_to_add) + "\n")
    except Exception as e:
        logger.warning("Could not write /etc/hosts: %s", e)
        return []
    return added


def remove_hosts(job_id: Optional[str] = None) -> int:
    """Strip autopwn-managed entries from /etc/hosts. If job_id is None, removes all
    autopwn entries. Returns the number of lines removed."""
    if not is_root() or not HOSTS_FILE.exists():
        return 0
    try:
        original = HOSTS_FILE.read_text()
    except Exception as e:
        logger.warning("Could not read /etc/hosts: %s", e)
        return 0

    marker = f"{AUTOPWN_MARKER} job={job_id}" if job_id else AUTOPWN_MARKER
    kept = [line for line in original.splitlines() if marker not in line]
    removed = len(original.splitlines()) - len(kept)
    if removed == 0:
        return 0

    try:
        HOSTS_FILE.write_text("\n".join(kept) + "\n")
    except Exception as e:
        logger.warning("Could not write /etc/hosts: %s", e)
        return 0
    logger.info("Removed %d /etc/hosts entries for job=%s", removed, job_id or "*")
    return removed


def list_hosts(job_id: Optional[str] = None) -> list[dict]:
    """Return autopwn-managed entries as [{ip, hostname, job_id}, ...].
    If job_id is provided, returns only entries for that job."""
    if not HOSTS_FILE.exists():
        return []
    try:
        content = HOSTS_FILE.read_text()
    except Exception:
        return []
    out: list[dict] = []
    for line in content.splitlines():
        if AUTOPWN_MARKER not in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        entry_job_id: Optional[str] = None
        for p in parts:
            if p.startswith("job="):
                entry_job_id = p.split("=", 1)[1]
                break
        if job_id is not None and entry_job_id != job_id:
            continue
        out.append({"ip": parts[0], "hostname": parts[1], "job_id": entry_job_id})
    return out
