from __future__ import annotations
from fastapi import APIRouter, HTTPException, Depends
from ...core.dependency_checker import get_all_statuses, get_tool_status, run_dependency_check
from ...core.auth import require_token
import asyncio

router = APIRouter(prefix="/api/v1/tools", tags=["tools"],
                   dependencies=[Depends(require_token)])


@router.get("")
async def list_tools():
    return get_all_statuses()


@router.get("/{name}")
async def get_tool(name: str):
    status = get_tool_status(name)
    if not status:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' not in registry")
    return {
        "name": status.name, "status": status.status,
        "version": status.version, "required": status.required,
        "category": status.category, "description": status.description,
        "install_method": status.install_method, "message": status.message,
    }


@router.post("/check-all")
async def check_all_tools():
    result = await run_dependency_check()
    return result


@router.post("/{name}/install")
async def install_tool_endpoint(name: str):
    """Trigger install in background — use WS /ws/tools/{name}/install for live output."""
    from ...core.dependency_checker import install_tool
    asyncio.create_task(install_tool(name))
    return {"message": f"Install triggered for {name}. Connect to /ws/tools/{name}/install for live output."}


@router.post("/{name}/update")
async def update_tool_endpoint(name: str):
    from ...core.dependency_checker import install_tool
    asyncio.create_task(install_tool(name))
    return {"message": f"Update triggered for {name}. Connect to /ws/tools/{name}/install for live output."}
