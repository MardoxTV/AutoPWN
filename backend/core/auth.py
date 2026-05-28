from __future__ import annotations
import os
from fastapi import Header, HTTPException


def get_api_token() -> str:
    """Read token at call time so .env reloads and test overrides work."""
    return os.getenv("AUTOPWN_API_TOKEN", "")


async def require_token(authorization: str = Header(default="")) -> None:
    """FastAPI dependency — enforce Bearer token when AUTOPWN_API_TOKEN is set."""
    token_env = get_api_token()
    if not token_env:
        return  # dev mode: no token configured, allow all
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or token != token_env:
        raise HTTPException(status_code=401, detail="Invalid or missing API token")
