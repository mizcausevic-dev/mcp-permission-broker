"""mcp-permission-broker — embeddable policy rule evaluator.

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
    TrustedCardContext,
)

__all__ = [
    "Broker",
    "Outcome",
    "PermissionDecision",
    "PermissionRequest",
    "PolicyBundle",
    "PolicyRule",
    "TrustedCardContext",
]
__version__ = "0.1.0"
