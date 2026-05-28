from __future__ import annotations
import yaml
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional

from ...core.auth import require_token

router = APIRouter(prefix="/api/v1/settings", tags=["settings"],
                   dependencies=[Depends(require_token)])

SETTINGS_PATH = Path(__file__).parent.parent.parent.parent / "config" / "settings.yaml"
_settings_cache: dict = {}


def _load_settings() -> dict:
    global _settings_cache
    if _settings_cache:
        return _settings_cache
    try:
        with open(SETTINGS_PATH) as f:
            _settings_cache = yaml.safe_load(f) or {}
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Cannot read settings file: {e}")
    return _settings_cache


# Pydantic models — only the fields the UI actually exposes for editing.
# Using these instead of a bare dict prevents arbitrary key injection.

class NetworkUpdate(BaseModel):
    vpn_interface: Optional[str] = None
    default_timeout_s: Optional[int] = Field(default=None, ge=1, le=300)
    scan_rate: Optional[int] = Field(default=None, ge=1, le=10000)


class MsfrpcUpdate(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    username: Optional[str] = None
    password: Optional[str] = None  # written to settings.yaml only; env var takes precedence at runtime
    ssl: Optional[bool] = None
    startup_wait_s: Optional[int] = Field(default=None, ge=5, le=300)


class ServerUpdate(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)


class ScannerUpdate(BaseModel):
    host: Optional[str] = None
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    startup_timeout_s: Optional[int] = Field(default=None, ge=1, le=120)


class SettingsUpdate(BaseModel):
    network: Optional[NetworkUpdate] = None
    server: Optional[ServerUpdate] = None
    msfrpc: Optional[MsfrpcUpdate] = None
    scanner_service: Optional[ScannerUpdate] = None


@router.get("")
async def get_settings():
    return _load_settings()


@router.put("")
async def update_settings(updates: SettingsUpdate):
    global _settings_cache
    settings = _load_settings()

    def _merge(target: dict, patch: BaseModel):
        for field, value in patch.model_dump(exclude_none=True).items():
            target[field] = value

    if updates.network:
        settings.setdefault("network", {})
        _merge(settings["network"], updates.network)
    if updates.server:
        settings.setdefault("server", {})
        _merge(settings["server"], updates.server)
    if updates.msfrpc:
        settings.setdefault("msfrpc", {})
        _merge(settings["msfrpc"], updates.msfrpc)
    if updates.scanner_service:
        settings.setdefault("scanner_service", {})
        _merge(settings["scanner_service"], updates.scanner_service)

    try:
        with open(SETTINGS_PATH, "w") as f:
            yaml.dump(settings, f, default_flow_style=False)
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Cannot write settings file: {e}")

    _settings_cache = settings
    return settings
