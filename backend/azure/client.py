from __future__ import annotations
import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger("autopwn.azure.client")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA = "https://graph.microsoft.com/beta"
ARM_BASE = "https://management.azure.com"


class AzureAPIError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(f"HTTP {status_code}: {message}")


class PermissionError(AzureAPIError):
    pass


class GraphClient:
    def __init__(self, token: str, beta: bool = False):
        self._token = token
        self._base = GRAPH_BETA if beta else GRAPH_BASE
        self._client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )

    def beta_view(self) -> "GraphClient":
        """Returns a GraphClient sharing the same httpx session but using the beta endpoint."""
        view = GraphClient.__new__(GraphClient)
        view._token = self._token
        view._base = GRAPH_BETA
        view._client = self._client
        return view

    async def get(self, path: str, params: dict[str, Any] | None = None) -> dict:
        url = f"{self._base}{path}"
        for _ in range(3):
            r = await self._client.get(url, params=params)
            if r.status_code == 429:
                await asyncio.sleep(int(r.headers.get("Retry-After", "10")))
                continue
            if r.status_code == 403:
                raise PermissionError(403, path)
            if r.status_code == 404:
                return {}
            if not r.is_success:
                raise AzureAPIError(r.status_code, r.text[:300])
            return r.json()
        raise AzureAPIError(429, "Rate limited after retries")

    async def get_all_pages(
        self, path: str, params: dict[str, Any] | None = None, max_items: int = 5000
    ) -> list[dict]:
        items: list[dict] = []
        url: str | None = f"{self._base}{path}"
        first = True
        while url and len(items) < max_items:
            for _ in range(3):
                r = await self._client.get(url, params=params if first else None)
                if r.status_code == 429:
                    await asyncio.sleep(int(r.headers.get("Retry-After", "10")))
                    continue
                if r.status_code == 403:
                    raise PermissionError(403, path)
                if r.status_code == 404:
                    return items
                if not r.is_success:
                    raise AzureAPIError(r.status_code, r.text[:300])
                data = r.json()
                items.extend(data.get("value", []))
                url = data.get("@odata.nextLink")
                first = False
                break
        return items

    async def close(self) -> None:
        await self._client.aclose()


class ARMClient:
    def __init__(self, token: str):
        self._client = httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"},
            timeout=30.0,
        )

    async def get(self, path: str, api_version: str, params: dict[str, Any] | None = None) -> dict:
        url = f"{ARM_BASE}{path}"
        p = {"api-version": api_version, **(params or {})}
        for _ in range(3):
            r = await self._client.get(url, params=p)
            if r.status_code == 429:
                await asyncio.sleep(int(r.headers.get("Retry-After", "10")))
                continue
            if r.status_code == 403:
                raise PermissionError(403, path)
            if r.status_code == 404:
                return {}
            if not r.is_success:
                raise AzureAPIError(r.status_code, r.text[:300])
            return r.json()
        raise AzureAPIError(429, "Rate limited after retries")

    async def get_list(self, path: str, api_version: str) -> list[dict]:
        data = await self.get(path, api_version)
        return data.get("value", [])

    async def close(self) -> None:
        await self._client.aclose()
