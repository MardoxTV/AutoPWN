from .jobs import router as jobs_router
from .results import router as results_router
from .tools import router as tools_router
from .settings import router as settings_router
from .reports import router as reports_router
from .azure import router as azure_router

__all__ = ["jobs_router", "results_router", "tools_router", "settings_router", "reports_router", "azure_router"]
