from __future__ import annotations
import asyncio
import re
import shutil
import socket
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from packaging.version import Version, InvalidVersion

from ..tool_registry import get_registry, ToolSpec
from ..tool_registry.registry import PipPackageSpec

logger = logging.getLogger("autopwn.deps")

_status_cache: dict[str, "ToolStatus"] = {}
_pip_cache: dict[str, "ToolStatus"] = {}
_network_cache: dict[str, bool] = {}


@dataclass
class ToolStatus:
    name: str
    status: str  # ok | missing | outdated | timeout | error
    version: Optional[str] = None
    required: bool = False
    category: str = ""
    description: str = ""
    install_method: str = ""
    message: Optional[str] = None


async def _run_check(cmd: list[str], timeout: float = 10.0) -> tuple[int, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            return proc.returncode or 0, stdout.decode(errors="replace")
        except asyncio.TimeoutError:
            proc.kill()
            return -1, "timeout"
    except FileNotFoundError:
        return -2, "not_found"
    except Exception as e:
        return -3, str(e)


def _compare_versions(captured: str, min_ver: str) -> bool:
    try:
        return Version(captured) >= Version(min_ver)
    except InvalidVersion:
        return True  # can't compare, assume ok


def _base_status(tool: ToolSpec, **kw) -> ToolStatus:
    return ToolStatus(
        name=tool.name, required=tool.required,
        category=tool.category, description=tool.description,
        install_method=tool.install.method, **kw,
    )


async def _check_tool(tool: ToolSpec) -> ToolStatus:
    # 1. Definitive presence check — binary in PATH, or downloaded file on disk
    if tool.binary:
        if not shutil.which(tool.binary):
            return _base_status(tool, status="missing")
    elif tool.install.method == "download" and tool.install.destination:
        if not Path(tool.install.destination).exists():
            return _base_status(tool, status="missing")
    # else: tool has no binary and isn't a download (e.g. impacket python lib)
    #       — fall through to the command check below as the sole signal

    # 2. Best-effort version detection — never fails the check if binary already exists
    version: Optional[str] = None
    output = ""
    if tool.check.command:
        code, output = await _run_check(tool.check.command)
        if code == -1:
            return _base_status(tool, status="timeout")
        # If the tool has no binary AND the command itself wasn't found, mark missing.
        if not tool.binary and tool.install.method != "download" and code == -2:
            return _base_status(tool, status="missing")

        if tool.check.output_pattern:
            match = re.search(tool.check.output_pattern, output, re.IGNORECASE)
            if match and tool.check.version_group is not None:
                try:
                    version = match.group(tool.check.version_group)
                except IndexError:
                    pass

    # 3. Enforce min_version only if we successfully parsed a version
    if version and tool.check.min_version:
        if not _compare_versions(version, tool.check.min_version):
            return _base_status(
                tool, status="outdated", version=version,
                message=f"Installed: {version}, required: {tool.check.min_version}",
            )

    return _base_status(tool, status="ok", version=version)


async def _check_pip_package(pkg: PipPackageSpec) -> ToolStatus:
    code, _ = await _run_check(
        ["python3", "-c", f"import {pkg.check_import}"]
    )
    status = "ok" if code == 0 else "missing"
    return ToolStatus(
        name=pkg.name, status=status, category="python",
        install_method="pip",
    )


def _check_interface(iface: str) -> bool:
    try:
        import psutil
        addrs = psutil.net_if_addrs()
        return iface in addrs
    except Exception:
        return False


async def run_dependency_check() -> dict:
    registry = get_registry()

    tool_tasks = [_check_tool(t) for t in registry.tools]
    pip_tasks = [_check_pip_package(p) for p in registry.pip_packages]

    tool_results, pip_results = await asyncio.gather(
        asyncio.gather(*tool_tasks),
        asyncio.gather(*pip_tasks),
    )

    for ts in tool_results:
        _status_cache[ts.name] = ts

    for ps in pip_results:
        _pip_cache[ps.name] = ps

    for prereq in registry.network_prerequisites:
        if prereq.check == "interface_exists":
            up = _check_interface(prereq.name)
            _network_cache[prereq.name] = up
            if not up:
                logger.warning(prereq.warning)

    ok = sum(1 for s in _status_cache.values() if s.status == "ok")
    missing = [s.name for s in _status_cache.values() if s.status == "missing"]
    outdated = [s.name for s in _status_cache.values() if s.status == "outdated"]

    logger.info(
        f"Dependency check complete: {ok} OK"
        + (f", {len(missing)} MISSING ({', '.join(missing)})" if missing else "")
        + (f", {len(outdated)} OUTDATED ({', '.join(outdated)})" if outdated else "")
    )

    return get_all_statuses()


def get_all_statuses() -> dict:
    return {
        "tools": {k: _tool_status_to_dict(v) for k, v in _status_cache.items()},
        "pip_packages": {k: _tool_status_to_dict(v) for k, v in _pip_cache.items()},
        "network": _network_cache,
    }


def get_tool_status(name: str) -> Optional[ToolStatus]:
    return _status_cache.get(name) or _pip_cache.get(name)


def _tool_status_to_dict(ts: ToolStatus) -> dict:
    return {
        "name": ts.name,
        "status": ts.status,
        "version": ts.version,
        "required": ts.required,
        "category": ts.category,
        "description": ts.description,
        "install_method": ts.install_method,
        "message": ts.message,
    }


async def install_tool(name: str, log_callback=None) -> bool:
    registry = get_registry()
    tool = registry.get_tool(name)
    if not tool:
        return False

    spec = tool.install
    cmd = _build_install_cmd(spec)
    if not cmd:
        return False

    if log_callback:
        await log_callback(f"Installing {name}...")

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    async for line in proc.stdout:
        if log_callback:
            await log_callback(line.decode(errors="replace").rstrip())

    await proc.wait()
    success = proc.returncode == 0

    if spec.chmod and spec.destination and success:
        await asyncio.create_subprocess_exec("chmod", spec.chmod, spec.destination)

    # Re-check and update cache
    new_status = await _check_tool(tool)
    _status_cache[name] = new_status

    return success


def _build_install_cmd(spec) -> Optional[list[str]]:
    if spec.method == "apt":
        return ["apt-get", "install", "-y", spec.package]
    elif spec.method == "pip":
        return ["pip3", "install", "--break-system-packages", spec.package]
    elif spec.method == "gem":
        return ["gem", "install", spec.package]
    elif spec.method == "download":
        Path(spec.destination).parent.mkdir(parents=True, exist_ok=True)
        return ["curl", "-fsSL", "-o", spec.destination, spec.url]
    elif spec.method == "custom":
        return spec.command
    return None


async def install_missing(log_callback=None) -> dict:
    """Sequentially install every tool currently flagged as missing.
    Returns {tool_name: success_bool} for everything attempted."""
    missing = [name for name, s in _status_cache.items() if s.status == "missing"]
    results: dict[str, bool] = {}

    if log_callback:
        await log_callback(f"Installing {len(missing)} missing tools: {', '.join(missing) or '(none)'}")

    for name in missing:
        if log_callback:
            await log_callback(f"\n=== {name} ===")
        try:
            ok = await install_tool(name, log_callback=log_callback)
        except Exception as e:
            ok = False
            if log_callback:
                await log_callback(f"ERROR installing {name}: {e}")
        results[name] = ok

    if log_callback:
        succeeded = [n for n, ok in results.items() if ok]
        failed = [n for n, ok in results.items() if not ok]
        await log_callback(f"\nDone. Installed: {len(succeeded)}, Failed: {len(failed)}")
        if failed:
            await log_callback(f"Failed tools: {', '.join(failed)}")

    return results
