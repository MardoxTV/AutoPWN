from __future__ import annotations
import asyncio
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

# msal is an optional dependency — backend starts fine without it.
# Azure endpoints will return a 503 if it isn't installed.
try:
    import msal as _msal
    _MSAL_AVAILABLE = True
except ImportError:
    _msal = None  # type: ignore[assignment]
    _MSAL_AVAILABLE = False

logger = logging.getLogger("autopwn.azure.auth")
if not _MSAL_AVAILABLE:
    logger.warning("msal not installed — Azure auth endpoints will return 503. Install with: pip install msal")

AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]
ARM_SCOPES = ["https://management.azure.com/.default"]

_executor = ThreadPoolExecutor(max_workers=5)
_auth_sessions: dict[str, dict] = {}


def create_session_id() -> str:
    return str(uuid.uuid4())


def get_session(session_id: str) -> Optional[dict]:
    return _auth_sessions.get(session_id)


def start_device_flow(session_id: str) -> dict:
    if not _MSAL_AVAILABLE:
        raise RuntimeError(
            "msal is not installed. Install it with: pip install msal"
        )
    app = _msal.PublicClientApplication(
        client_id=AZURE_CLI_CLIENT_ID,
        authority="https://login.microsoftonline.com/common",
    )
    flow = app.initiate_device_flow(scopes=GRAPH_SCOPES)
    if "error" in flow:
        raise RuntimeError(
            f"Failed to start device flow: {flow.get('error_description', flow['error'])}"
        )

    _auth_sessions[session_id] = {
        "msal_app": app,
        "flow": flow,
        "status": "pending",
        "graph_token": None,
        "arm_token": None,
        "tenant_id": None,
        "user_name": None,
        "error": None,
    }
    return {
        "user_code": flow["user_code"],
        "verification_uri": flow["verification_uri"],
        "expires_in": flow["expires_in"],
        "message": flow.get("message", ""),
    }


async def run_device_flow_background(session_id: str) -> None:
    """Acquires Graph token in a thread, then tries ARM silent."""
    session = _auth_sessions[session_id]
    app = session["msal_app"]
    flow = session["flow"]

    loop = asyncio.get_event_loop()
    result: dict = await loop.run_in_executor(
        _executor,
        lambda: app.acquire_token_by_device_flow(flow),
    )

    if "access_token" in result:
        session["graph_token"] = result["access_token"]
        claims: dict = result.get("id_token_claims") or {}
        session["tenant_id"] = claims.get("tid", "unknown")
        session["user_name"] = claims.get("name") or claims.get("preferred_username", "Unknown")

        # Try to get an ARM token from the cached account without a second device prompt
        accounts = app.get_accounts()
        if accounts:
            arm_result = app.acquire_token_silent(ARM_SCOPES, account=accounts[0])
            if arm_result and "access_token" in arm_result:
                session["arm_token"] = arm_result["access_token"]
                logger.info("ARM token acquired silently for session %s", session_id)
            else:
                logger.info(
                    "ARM silent token failed for session %s — ARM checks will be skipped", session_id
                )

        session["status"] = "success"
        logger.info(
            "Auth complete for session %s (tenant=%s user=%s)",
            session_id, session["tenant_id"], session["user_name"],
        )
    else:
        err = result.get("error", "unknown")
        session["status"] = "error"
        session["error"] = result.get("error_description", err)
        logger.warning("Auth failed for session %s: %s", session_id, session["error"])
