"""
MCP Sideport Daemon

HTTP server that serves MCP App UIs in browser with REST API fallback.
Works with AI coding tools to provide browser-based dashboards.
"""

import asyncio
import json
import logging
import os
import time
import webbrowser
from pathlib import Path
from typing import Any, Callable, Optional
from uuid import uuid4

from aiohttp import web

logger = logging.getLogger("mcp_sideport")


class SideportDaemon:
    """
    HTTP server for MCP App UI rendering with REST API fallback.

    Endpoints:
    - POST /launch - Open browser with MCP App, returns sessionId
    - GET /app/{id} - Serve sandboxed host page
    - GET /dashboard - Direct dashboard access (no sandbox)
    - GET /api/* - REST API endpoints for dashboard data
    - POST /api/action - Execute actions
    - GET /health - Health check
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3847,
        mcp_server_url: Optional[str] = None,
        auto_open_browser: bool = True,
        action_handlers: Optional[dict[str, Callable]] = None,
        api_handlers: Optional[dict[str, Callable]] = None,
    ):
        """
        Initialize the sideport daemon.

        Args:
            host: Host to bind to
            port: Port to listen on
            mcp_server_url: URL of MCP server to fetch UI from (enables HMR)
            auto_open_browser: Auto-open browser on /launch
            action_handlers: Custom action handlers for POST /api/action
            api_handlers: Custom GET API handlers for /api/{name}
        """
        self.host = host
        self.port = port
        self.mcp_server_url = mcp_server_url or os.environ.get("MCP_SERVER_URL")
        self.auto_open_browser = auto_open_browser
        self.action_handlers = action_handlers or {}
        self.api_handlers = api_handlers or {}

        # Session storage: session_id -> session data
        self.sessions: dict[str, dict] = {}
        # Agent index: agent_id -> list of session_ids (one agent can have multiple sessions)
        self.agent_sessions: dict[str, list[str]] = {}
        self.content_cache: dict[str, str] = {}
        self._html_cache: dict = {"html": None, "time": 0, "mcp_session_id": None}

        self.app = self._create_app()

    def _create_app(self) -> web.Application:
        """Create aiohttp application with routes."""
        app = web.Application()

        # Core routes
        app.router.add_post("/launch", self.handle_launch)
        app.router.add_get("/app/{session_id}", self.handle_app)
        app.router.add_get("/dashboard", self.handle_dashboard)
        app.router.add_get("/health", self.handle_health)

        # Session management routes
        app.router.add_get("/sessions", self.handle_list_sessions)
        app.router.add_get("/sessions/{session_id}", self.handle_get_session)
        app.router.add_delete("/sessions/{session_id}", self.handle_delete_session)
        app.router.add_options("/sessions/{session_id}", self.handle_cors_preflight)

        # API routes
        app.router.add_get("/api/{name}", self.handle_api_get)
        app.router.add_post("/api/action", self.handle_api_action)
        app.router.add_options("/api/action", self.handle_cors_preflight)

        return app

    def register_action(self, name: str, handler: Callable) -> None:
        """Register a custom action handler."""
        self.action_handlers[name] = handler

    def register_api(self, name: str, handler: Callable) -> None:
        """Register a custom GET API handler."""
        self.api_handlers[name] = handler

    async def handle_launch(self, request: web.Request) -> web.Response:
        """POST /launch - Open browser with MCP App."""
        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)

        resource_uri = data.get("resourceUri")
        title = data.get("title", "MCP App")
        agent_id = data.get("agentId")  # Claude Code conversation/session ID

        if not resource_uri:
            return web.json_response({"error": "resourceUri required"}, status=400)

        # Create session paired with agent
        session_id = str(uuid4())
        session = {
            "sessionId": session_id,
            "agentId": agent_id,
            "resourceUri": resource_uri,
            "title": title,
            "created": time.time(),
            "status": "pending",
        }
        self.sessions[session_id] = session

        # Index by agent_id for lookups
        if agent_id:
            if agent_id not in self.agent_sessions:
                self.agent_sessions[agent_id] = []
            self.agent_sessions[agent_id].append(session_id)

        app_url = f"http://{self.host}:{self.port}/app/{session_id}"

        # Fetch content in background
        asyncio.create_task(self._fetch_content(session_id, resource_uri))

        # Open browser
        if self.auto_open_browser:
            try:
                webbrowser.open(app_url)
                logger.info(f"Opened browser for session {session_id} (agent: {agent_id})")
            except Exception as e:
                logger.warning(f"Failed to open browser: {e}")

        return web.json_response({
            "sessionId": session_id,
            "agentId": agent_id,
            "status": "pending",
            "appUrl": app_url,
        })

    async def _fetch_content(self, session_id: str, resource_uri: str) -> None:
        """Fetch content from MCP server or use placeholder."""
        # Placeholder while loading
        self.content_cache[session_id] = self._loading_html(resource_uri)

        if self.mcp_server_url:
            try:
                html = await self._fetch_from_mcp(resource_uri)
                if html:
                    self.content_cache[session_id] = html
                    if session_id in self.sessions:
                        self.sessions[session_id]["status"] = "ready"
                    return
            except Exception as e:
                logger.warning(f"Failed to fetch from MCP: {e}")
                if session_id in self.sessions:
                    self.sessions[session_id]["status"] = "error"
                    self.sessions[session_id]["error"] = str(e)

    async def _fetch_from_mcp(self, resource_uri: str) -> Optional[str]:
        """Fetch HTML from MCP server resource endpoint."""
        import aiohttp

        async with aiohttp.ClientSession() as session:
            # Initialize MCP session if needed
            mcp_session_id = self._html_cache.get("mcp_session_id")

            if not mcp_session_id:
                init_resp = await session.post(
                    f"{self.mcp_server_url}/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-03-26",
                            "capabilities": {},
                            "clientInfo": {"name": "mcp-sideport", "version": "1.0.0"},
                        },
                    },
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                )
                mcp_session_id = init_resp.headers.get("mcp-session-id")
                self._html_cache["mcp_session_id"] = mcp_session_id

            if mcp_session_id:
                # Fetch resource
                res_resp = await session.post(
                    f"{self.mcp_server_url}/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "resources/read",
                        "params": {"uri": resource_uri},
                    },
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                        "Mcp-Session-Id": mcp_session_id,
                    },
                )
                text = await res_resp.text()

                # Parse SSE response
                for line in text.split("\n"):
                    if line.startswith("data: "):
                        data = json.loads(line[6:])
                        if "result" in data and "contents" in data["result"]:
                            return data["result"]["contents"][0].get("text", "")

        return None

    def _loading_html(self, resource_uri: str) -> str:
        """Generate loading placeholder HTML."""
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: -apple-system, sans-serif;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    margin: 0;
                    background: #1a1a2e;
                    color: #eee;
                }}
                .spinner {{
                    width: 40px;
                    height: 40px;
                    border: 3px solid #333;
                    border-top-color: #00d9ff;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                    margin: 0 auto 16px;
                }}
                @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
            </style>
        </head>
        <body>
            <div style="text-align: center;">
                <div class="spinner"></div>
                <p>Loading MCP App...</p>
                <p style="font-size: 12px; opacity: 0.6;">{resource_uri}</p>
            </div>
        </body>
        </html>
        """

    async def handle_app(self, request: web.Request) -> web.Response:
        """GET /app/{session_id} - Serve sandboxed app page."""
        session_id = request.match_info["session_id"]
        session = self.sessions.get(session_id)

        if not session:
            return web.Response(text="Session not found", status=404)

        content = self.content_cache.get(session_id, "<p>Loading...</p>")

        return web.Response(
            text=content,
            content_type="text/html",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )

    async def handle_dashboard(self, request: web.Request) -> web.Response:
        """GET /dashboard - Direct dashboard access with HMR support."""
        now = time.time()
        cache = self._html_cache

        # Short cache to allow HMR polling without flooding MCP server
        if cache["html"] and (now - cache["time"]) < 0.1:
            return web.Response(
                text=cache["html"],
                content_type="text/html",
                headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
            )

        # Try to fetch from MCP server
        if self.mcp_server_url:
            try:
                html = await self._fetch_from_mcp("ui://dashboard/main")
                if html:
                    cache["html"] = html
                    cache["time"] = now
                    return web.Response(
                        text=html,
                        content_type="text/html",
                        headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
                    )
            except Exception as e:
                logger.warning(f"Failed to fetch dashboard from MCP: {e}")
                cache["mcp_session_id"] = None

        # Fallback to static file
        static_file = Path(__file__).parent / "static" / "dashboard.html"
        if static_file.exists():
            return web.Response(
                text=static_file.read_text(),
                content_type="text/html",
            )

        return web.Response(text="Dashboard not found", status=404)

    async def handle_health(self, request: web.Request) -> web.Response:
        """GET /health - Health check."""
        return web.json_response({
            "status": "ok",
            "sessions": len(self.sessions),
            "agents": len(self.agent_sessions),
            "mcp_server": self.mcp_server_url or "not configured",
        })

    async def handle_list_sessions(self, request: web.Request) -> web.Response:
        """GET /sessions - List sessions, optionally filtered by agent_id."""
        cors_headers = {"Access-Control-Allow-Origin": "*"}
        agent_id = request.query.get("agentId")

        if agent_id:
            # Return sessions for specific agent
            session_ids = self.agent_sessions.get(agent_id, [])
            sessions = [self.sessions[sid] for sid in session_ids if sid in self.sessions]
        else:
            # Return all sessions
            sessions = list(self.sessions.values())

        return web.json_response({"sessions": sessions}, headers=cors_headers)

    async def handle_get_session(self, request: web.Request) -> web.Response:
        """GET /sessions/{session_id} - Get session details."""
        cors_headers = {"Access-Control-Allow-Origin": "*"}
        session_id = request.match_info["session_id"]

        session = self.sessions.get(session_id)
        if not session:
            return web.json_response(
                {"error": "Session not found"},
                status=404,
                headers=cors_headers,
            )

        return web.json_response(session, headers=cors_headers)

    async def handle_delete_session(self, request: web.Request) -> web.Response:
        """DELETE /sessions/{session_id} - Close and remove a session."""
        cors_headers = {"Access-Control-Allow-Origin": "*"}
        session_id = request.match_info["session_id"]

        session = self.sessions.get(session_id)
        if not session:
            return web.json_response(
                {"error": "Session not found"},
                status=404,
                headers=cors_headers,
            )

        # Remove from agent index
        agent_id = session.get("agentId")
        if agent_id and agent_id in self.agent_sessions:
            self.agent_sessions[agent_id] = [
                sid for sid in self.agent_sessions[agent_id] if sid != session_id
            ]
            # Clean up empty agent entries
            if not self.agent_sessions[agent_id]:
                del self.agent_sessions[agent_id]

        # Remove session and cached content
        del self.sessions[session_id]
        self.content_cache.pop(session_id, None)

        return web.json_response({"status": "deleted", "sessionId": session_id}, headers=cors_headers)

    async def handle_cors_preflight(self, request: web.Request) -> web.Response:
        """Handle CORS preflight."""
        return web.Response(
            status=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type",
            },
        )

    async def handle_api_get(self, request: web.Request) -> web.Response:
        """GET /api/{name} - Custom API handlers."""
        name = request.match_info["name"]
        cors_headers = {"Access-Control-Allow-Origin": "*"}

        handler = self.api_handlers.get(name)
        if not handler:
            return web.json_response(
                {"error": f"Unknown API: {name}"},
                status=404,
                headers=cors_headers,
            )

        try:
            args = dict(request.query)
            # Support both sync and async handlers
            if asyncio.iscoroutinefunction(handler):
                result = await handler(**args) if args else await handler()
            else:
                result = handler(**args) if args else handler()
            return web.json_response(result, headers=cors_headers)
        except Exception as e:
            logger.error(f"API error ({name}): {e}")
            return web.json_response({"error": str(e)}, status=500, headers=cors_headers)

    async def handle_api_action(self, request: web.Request) -> web.Response:
        """POST /api/action - Execute actions."""
        cors_headers = {"Access-Control-Allow-Origin": "*"}

        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400, headers=cors_headers)

        action = data.get("action")
        args = data.get("args", {})

        if not action:
            return web.json_response({"error": "action required"}, status=400, headers=cors_headers)

        handler = self.action_handlers.get(action)
        if not handler:
            return web.json_response(
                {"error": f"Unknown action: {action}"},
                status=400,
                headers=cors_headers,
            )

        try:
            # Support both sync and async handlers
            if asyncio.iscoroutinefunction(handler):
                result = await handler(**args)
            else:
                result = handler(**args)
            return web.json_response(result, headers=cors_headers)
        except Exception as e:
            logger.error(f"Action error ({action}): {e}")
            return web.json_response({"error": str(e)}, status=500, headers=cors_headers)

    def run(self) -> None:
        """Start the daemon (blocking)."""
        logger.info(f"Starting mcp-sideport on {self.host}:{self.port}")
        if self.mcp_server_url:
            logger.info(f"MCP Server: {self.mcp_server_url}")
        web.run_app(self.app, host=self.host, port=self.port, print=None)


def run_sideport(
    host: str = "127.0.0.1",
    port: int = 3847,
    mcp_server_url: Optional[str] = None,
) -> None:
    """Run the sideport daemon."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    daemon = SideportDaemon(host=host, port=port, mcp_server_url=mcp_server_url)
    daemon.run()


def main():
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="mcp-sideport - MCP Apps bridge for AI coding tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  mcp-sideport --port 3847 --mcp-server http://127.0.0.1:3850
  MCP_SERVER_URL=http://127.0.0.1:3850 mcp-sideport
  uvx mcp-sideport --help
        """,
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=3847, help="Port to listen on")
    parser.add_argument("--mcp-server", help="MCP server URL (enables HMR)")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open browser")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    daemon = SideportDaemon(
        host=args.host,
        port=args.port,
        mcp_server_url=args.mcp_server or os.environ.get("MCP_SERVER_URL"),
        auto_open_browser=not args.no_browser,
    )
    daemon.run()


if __name__ == "__main__":
    main()
