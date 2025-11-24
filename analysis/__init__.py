"""
Analysis modules for mapping WatchGuard objects to FMC.
"""

from .service_mapper import ServiceMapper
from .app_mapper import ApplicationMapper

__all__ = ["ServiceMapper", "ApplicationMapper"]
