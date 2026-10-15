"""Local-only configuration UI (no authentication, binds 127.0.0.1)."""
from app.web.handler import PAGE, Handler
from app.web.server import (
    ExclusiveThreadingHTTPServer,
    _bootstrap_config,
    _startup_banner,
    main,
)
from app.web.service import WebService, _compact_configuration_label

__all__ = ["PAGE", "ExclusiveThreadingHTTPServer", "Handler", "WebService", "main",
           "_bootstrap_config", "_compact_configuration_label", "_startup_banner"]
