from __future__ import annotations
import os
import yaml
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "tools.yaml"


@dataclass
class InstallSpec:
    method: str  # apt | pip | gem | download | custom
    package: Optional[str] = None
    url: Optional[str] = None
    destination: Optional[str] = None
    chmod: Optional[str] = None
    command: Optional[list[str]] = None


@dataclass
class CheckSpec:
    command: list[str]
    output_pattern: Optional[str] = None
    version_group: Optional[int] = None
    min_version: Optional[str] = None


@dataclass
class ToolSpec:
    name: str
    description: str
    category: str
    required: bool
    install: InstallSpec
    check: CheckSpec
    update: InstallSpec
    binary: Optional[str] = None
    fallback: Optional[str] = None


@dataclass
class PipPackageSpec:
    name: str
    install_command: list[str]
    check_import: str
    apt_package: Optional[str] = None


@dataclass
class NetworkPrerequisite:
    name: str
    description: str
    check: str
    warning: str


@dataclass
class ToolRegistry:
    tools: list[ToolSpec] = field(default_factory=list)
    pip_packages: list[PipPackageSpec] = field(default_factory=list)
    network_prerequisites: list[NetworkPrerequisite] = field(default_factory=list)

    def get_tool(self, name: str) -> Optional[ToolSpec]:
        return next((t for t in self.tools if t.name == name), None)

    def get_by_category(self, category: str) -> list[ToolSpec]:
        return [t for t in self.tools if t.category == category]

    def required_tools(self) -> list[ToolSpec]:
        return [t for t in self.tools if t.required]


def _parse_install(data: dict) -> InstallSpec:
    return InstallSpec(
        method=data["method"],
        package=data.get("package"),
        url=data.get("url"),
        destination=data.get("destination"),
        chmod=data.get("chmod"),
        command=data.get("command"),
    )


def load_registry(config_path: Path = CONFIG_PATH) -> ToolRegistry:
    with open(config_path, "r") as f:
        raw = yaml.safe_load(f)

    tools = []
    for t in raw.get("tools", []):
        tools.append(ToolSpec(
            name=t["name"],
            description=t["description"],
            category=t["category"],
            required=t.get("required", False),
            binary=t.get("binary"),
            fallback=t.get("fallback"),
            install=_parse_install(t["install"]),
            check=CheckSpec(
                command=t["check"]["command"],
                output_pattern=t["check"].get("output_pattern"),
                version_group=t["check"].get("version_group"),
                min_version=t["check"].get("min_version"),
            ),
            update=_parse_install(t["update"]),
        ))

    pip_packages = []
    for p in raw.get("pip_packages", []):
        pip_packages.append(PipPackageSpec(
            name=p["name"],
            install_command=p["install_command"],
            check_import=p["check_import"],
            apt_package=p.get("apt_package"),
        ))

    network_prereqs = []
    for n in raw.get("network_prerequisites", []):
        network_prereqs.append(NetworkPrerequisite(
            name=n["name"],
            description=n["description"],
            check=n["check"],
            warning=n["warning"],
        ))

    return ToolRegistry(tools=tools, pip_packages=pip_packages,
                        network_prerequisites=network_prereqs)


_registry: Optional[ToolRegistry] = None


def get_registry() -> ToolRegistry:
    global _registry
    if _registry is None:
        _registry = load_registry()
    return _registry
