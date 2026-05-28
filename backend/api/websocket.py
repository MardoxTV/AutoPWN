from __future__ import annotations
import asyncio
import json
import logging
from fastapi import WebSocket, WebSocketDisconnect
from ..core.event_bus import bus
from ..core.auth import get_api_token

logger = logging.getLogger("autopwn.ws")


async def _accept_or_reject(websocket: WebSocket) -> bool:
    """Verify ?token= query param when auth is enabled. Returns True if accepted."""
    token_env = get_api_token()
    if token_env:
        token = websocket.query_params.get("token", "")
        if token != token_env:
            await websocket.close(code=1008)  # 1008 = Policy Violation
            return False
    await websocket.accept()
    return True


async def job_log_ws(websocket: WebSocket, job_id: str):
    if not await _accept_or_reject(websocket):
        return
    queue = await bus.subscribe(job_id)
    logger.info(f"WebSocket client connected for job {job_id}")

    try:
        while True:
            # Race between new events and client messages (ping/disconnect)
            event_task = asyncio.create_task(queue.get())
            recv_task = asyncio.create_task(websocket.receive_text())

            done, pending = await asyncio.wait(
                [event_task, recv_task],
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in pending:
                task.cancel()

            if event_task in done:
                event = event_task.result()
                try:
                    await websocket.send_text(event.to_json())
                except (WebSocketDisconnect, RuntimeError):
                    # Client gone — stop the loop instead of crashing on the next iteration
                    break
            elif recv_task in done:
                try:
                    msg = recv_task.result()
                    data = json.loads(msg)
                    if data.get("type") == "ping":
                        await websocket.send_text(json.dumps({"type": "pong"}))
                except WebSocketDisconnect:
                    break
                except RuntimeError:
                    # Starlette throws RuntimeError if we try to receive after a disconnect message
                    break
                except json.JSONDecodeError:
                    pass  # tolerate garbage from client

    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected for job {job_id}")
    except Exception as e:
        logger.warning(f"WebSocket error for job {job_id}: {e}")
    finally:
        await bus.unsubscribe(job_id, queue)


async def tool_install_ws(websocket: WebSocket, tool_name: str):
    """Stream tool install progress.
    Special tool_name '_all' runs install_missing() for every missing tool."""
    if not await _accept_or_reject(websocket):
        return
    from ..core.dependency_checker import install_tool, install_missing

    async def send_line(line: str):
        await websocket.send_text(json.dumps({"type": "log", "message": line}))

    if tool_name == "_all":
        results = await install_missing(log_callback=send_line)
        await websocket.send_text(json.dumps({
            "type": "done",
            "success": all(results.values()) if results else True,
            "tool": "_all",
            "results": results,
        }))
    else:
        success = await install_tool(tool_name, log_callback=send_line)
        await websocket.send_text(json.dumps({
            "type": "done",
            "success": success,
            "tool": tool_name,
        }))
    await websocket.close()
