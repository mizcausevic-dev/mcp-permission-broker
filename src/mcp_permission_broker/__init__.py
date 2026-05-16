"""mcp-permission-broker — runtime gate for MCP tool invocations.

See README.md for design and usage. Public surface:

    from mcp_permission_broker import (
        Broker,
        PermissionRequest,
        PermissionDecision,
        PolicyRule,
        PolicyBundle,
        Outcome,
    )
"""

from mcp_permission_broker.broker import Broker
from mcp_permission_broker.models import (
    Outcome,
    PermissionDecision,
    PermissionRequest,
    PolicyBundle,
    PolicyRule,
)

__all__ = [
    "Broker",
    "Outcome",
    "PermissionDecision",
    "PermissionRequest",
    "PolicyBundle",
    "PolicyRule",
]
__version__ = "0.1.0"
