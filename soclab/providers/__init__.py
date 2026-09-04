"""Model providers behind one canonical interface.

Provider SDK types never leave their adapter module. Everything the rest of the
lab sees is a :class:`ModelRequest` in and a :class:`ModelResponse` out.
"""

from soclab.providers.base import (
    CapabilityUnsupportedError,
    MalformedResponseError,
    Message,
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ProviderError,
    ToolCall,
    ToolSpec,
)

__all__ = [
    "CapabilityUnsupportedError",
    "MalformedResponseError",
    "Message",
    "ModelProvider",
    "ModelRequest",
    "ModelResponse",
    "ProviderError",
    "ToolCall",
    "ToolSpec",
]
