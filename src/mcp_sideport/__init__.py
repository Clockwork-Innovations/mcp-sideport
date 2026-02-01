"""
mcp-sideport - MCP Apps bridge for AI coding tools

Enables browser UIs (MCP Apps) in CLI-based AI assistants with REST API fallback.
"""

__version__ = "0.1.0"

from .daemon import SideportDaemon, run_sideport
from .hybrid_api import generate_hybrid_api_script, wrap_html_with_hybrid_api

__all__ = [
    "SideportDaemon",
    "run_sideport",
    "generate_hybrid_api_script",
    "wrap_html_with_hybrid_api",
]
