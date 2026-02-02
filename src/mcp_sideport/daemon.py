"""
MCP Sideport Daemon

HTTP server that serves MCP App UIs in browser with REST API fallback.
Works with AI coding tools to provide browser-based dashboards.
"""

import asyncio
import html
import json
import logging
import os
import time
import webbrowser
from importlib.metadata import version as get_version
from pathlib import Path
from typing import Callable, Optional
from uuid import uuid4

import aiohttp
from aiohttp import web

logger = logging.getLogger("mcp_sideport")

# Default max request body size (1MB)
DEFAULT_CLIENT_MAX_SIZE = 1024 * 1024

# MCP fetch retry settings
MCP_FETCH_MAX_RETRIES = 2
MCP_FETCH_RETRY_DELAY = 0.5  # seconds

# MCP protocol version
MCP_PROTOCOL_VERSION = "2025-03-26"

# HTTP timeout for external requests (seconds)
HTTP_TIMEOUT = aiohttp.ClientTimeout(total=10)

# Session TTL in seconds (default 1 hour)
SESSION_TTL_SECONDS = 3600

# Session cleanup interval in seconds
SESSION_CLEANUP_INTERVAL = 300


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
        session_ttl: int = SESSION_TTL_SECONDS,
        client_max_size: int = DEFAULT_CLIENT_MAX_SIZE,
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
            session_ttl: Session time-to-live in seconds (default 1 hour)
            client_max_size: Max request body size in bytes (default 1MB)
        """
        self.host = host
        self.port = port
        self.mcp_server_url = mcp_server_url or os.environ.get("MCP_SERVER_URL")
        self.auto_open_browser = auto_open_browser
        self.action_handlers = action_handlers or {}
        self.api_handlers = api_handlers or {}
        self.session_ttl = session_ttl
        self.client_max_size = client_max_size

        # Track daemon start time for uptime reporting
        self._start_time = time.time()

        # Session storage
        self.sessions: dict[str, dict] = {}
        self.content_cache: dict[str, str] = {}
        self._html_cache: dict = {"html": None, "time": 0, "mcp_session_id": None}

        # Track background tasks to prevent fire-and-forget issues
        self._background_tasks: set[asyncio.Task] = set()

        # Cleanup task reference
        self._cleanup_task: Optional[asyncio.Task] = None

        # Shared HTTP client session (lazy initialized)
        self._client_session: Optional[aiohttp.ClientSession] = None
        self._session_lock = asyncio.Lock()

        # Lock for cache initialization to prevent race conditions
        self._init_lock = asyncio.Lock()

        self.app = self._create_app()

    def _create_app(self) -> web.Application:
        """Create aiohttp application with routes."""
        app = web.Application(client_max_size=self.client_max_size)

        # Core routes
        app.router.add_post("/launch", self.handle_launch)
        app.router.add_get("/app/{session_id}", self.handle_app)
        app.router.add_get("/dashboard", self.handle_dashboard)
        app.router.add_get("/health", self.handle_health)

        # API routes
        app.router.add_get("/api/{name}", self.handle_api_get)
        app.router.add_post("/api/action", self.handle_api_action)
        app.router.add_options("/api/action", self.handle_cors_preflight)

        return app

    def _on_task_done(self, task: asyncio.Task) -> None:
        """Callback for background task completion."""
        self._background_tasks.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc:
            logger.error(f"Background task failed: {exc}", exc_info=exc)

    def start_cleanup_task(self) -> None:
        """Start the session cleanup background task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
            self._cleanup_task.add_done_callback(self._on_task_done)

    async def _cleanup_loop(self) -> None:
        """Periodically clean up expired sessions."""
        while True:
            await asyncio.sleep(SESSION_CLEANUP_INTERVAL)
            self._cleanup_expired_sessions()

    def _cleanup_expired_sessions(self) -> None:
        """Remove sessions that have exceeded their TTL."""
        now = time.time()
        expired = [
            sid
            for sid, session in self.sessions.items()
            if now - session.get("created", 0) > self.session_ttl
        ]
        for sid in expired:
            self.close_session(sid)
            logger.info(f"Cleaned up expired session: {sid}")

    def close_session(self, session_id: str) -> bool:
        """Close and remove a session.

        Args:
            session_id: The session ID to close

        Returns:
            True if session was found and closed, False otherwise
        """
        if session_id in self.sessions:
            del self.sessions[session_id]
            self.content_cache.pop(session_id, None)
            return True
        return False

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

        if not resource_uri:
            return web.json_response({"error": "resourceUri required"}, status=400)

        # Create session
        session_id = str(uuid4())
        self.sessions[session_id] = {
            "sessionId": session_id,
            "resourceUri": resource_uri,
            "title": title,
            "created": time.time(),
            "status": "pending",
        }

        app_url = f"http://{self.host}:{self.port}/app/{session_id}"

        # Fetch content in background with proper task tracking
        task = asyncio.create_task(self._fetch_content(session_id, resource_uri))
        self._background_tasks.add(task)
        task.add_done_callback(self._on_task_done)

        # Open browser (in thread pool to avoid blocking)
        if self.auto_open_browser:
            try:
                await asyncio.to_thread(webbrowser.open, app_url)
                logger.info(f"Opened browser for session {session_id}")
            except Exception as e:
                logger.warning(f"Failed to open browser: {e}")

        return web.json_response(
            {
                "sessionId": session_id,
                "status": "pending",
                "appUrl": app_url,
            }
        )

    async def _fetch_content(self, session_id: str, resource_uri: str) -> None:
        """Fetch content from MCP server or use placeholder."""
        # Placeholder while loading
        self.content_cache[session_id] = self._loading_html(resource_uri)

        if self.mcp_server_url:
            try:
                html = await self._fetch_from_mcp(resource_uri)
                if html:
                    self.content_cache[session_id] = html
                    return
            except Exception as e:
                logger.warning(f"Failed to fetch from MCP: {e}")

    async def _get_client_session(self) -> aiohttp.ClientSession:
        """Get or create the shared HTTP client session."""
        if self._client_session is None or self._client_session.closed:
            async with self._session_lock:
                # Double-check after acquiring lock
                if self._client_session is None or self._client_session.closed:
                    self._client_session = aiohttp.ClientSession(timeout=HTTP_TIMEOUT)
        return self._client_session

    def _reset_mcp_session(self) -> None:
        """Reset the cached MCP session ID."""
        self._html_cache["mcp_session_id"] = None

    async def _fetch_from_mcp(
        self, resource_uri: str, _retry_count: int = 0
    ) -> Optional[str]:
        """Fetch HTML from MCP server resource endpoint.

        Includes retry logic with exponential backoff and session recovery.
        """
        session = await self._get_client_session()

        try:
            # Use lock to prevent race condition during MCP session initialization
            async with self._init_lock:
                mcp_session_id = self._html_cache.get("mcp_session_id")

                if not mcp_session_id:
                    init_resp = await session.post(
                        f"{self.mcp_server_url}/mcp",
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "initialize",
                            "params": {
                                "protocolVersion": MCP_PROTOCOL_VERSION,
                                "capabilities": {},
                                "clientInfo": {"name": "mcp-sideport", "version": "1.0.0"},
                            },
                        },
                        headers={
                            "Content-Type": "application/json",
                            "Accept": "application/json, text/event-stream",
                        },
                    )
                    # Check for session expiry/auth errors
                    if init_resp.status in (401, 404):
                        logger.warning(f"MCP init failed with status {init_resp.status}")
                        return None
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

                # Handle session expiry - reset and retry once
                if res_resp.status in (401, 404):
                    logger.warning(f"MCP session expired (status {res_resp.status}), resetting")
                    self._reset_mcp_session()
                    if _retry_count < 1:
                        return await self._fetch_from_mcp(resource_uri, _retry_count=1)
                    return None

                text = await res_resp.text()

                # Parse SSE response
                for line in text.split("\n"):
                    if line.startswith("data: "):
                        data = json.loads(line[6:])
                        if "result" in data and "contents" in data["result"]:
                            return data["result"]["contents"][0].get("text", "")

            return None

        except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as e:
            # Reset session on network/connection errors
            self._reset_mcp_session()

            # Retry with backoff if retries remain
            if _retry_count < MCP_FETCH_MAX_RETRIES:
                delay = MCP_FETCH_RETRY_DELAY * (2**_retry_count)
                logger.warning(
                    f"MCP fetch failed ({e}), retrying in {delay}s "
                    f"(attempt {_retry_count + 1}/{MCP_FETCH_MAX_RETRIES})"
                )
                await asyncio.sleep(delay)
                return await self._fetch_from_mcp(resource_uri, _retry_count=_retry_count + 1)

            logger.error(f"MCP fetch failed after {MCP_FETCH_MAX_RETRIES} retries: {e}")
            raise

    async def close(self) -> None:
        """Close the daemon and clean up resources."""
        # Cancel the cleanup task
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass

        # Cancel all background tasks
        for task in self._background_tasks:
            task.cancel()

        # Wait for tasks to complete
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)

        # Close the client session
        if self._client_session and not self._client_session.closed:
            await self._client_session.close()

        # Clear all sessions
        self.sessions.clear()
        self.content_cache.clear()

    def _loading_html(self, resource_uri: str) -> str:
        """Generate loading placeholder HTML."""
        # Escape resource_uri to prevent XSS
        safe_uri = html.escape(resource_uri)
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
                <p style="font-size: 12px; opacity: 0.6;">{safe_uri}</p>
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
                self._reset_mcp_session()

        # Fallback to static file (read in thread pool to avoid blocking)
        static_file = Path(__file__).parent / "static" / "dashboard.html"
        if static_file.exists():
            content = await asyncio.to_thread(static_file.read_text)
            return web.Response(
                text=content,
                content_type="text/html",
            )

        return web.Response(text="Dashboard not found", status=404)

    async def handle_health(self, request: web.Request) -> web.Response:
        """GET /health - Health check with detailed status."""
        # Get package version
        try:
            pkg_version = get_version("mcp-sideport")
        except Exception:
            pkg_version = "unknown"

        # Check if MCP server is reachable
        mcp_connected = False
        if self.mcp_server_url:
            try:
                session = await self._get_client_session()
                async with session.get(
                    f"{self.mcp_server_url}/health",
                    timeout=aiohttp.ClientTimeout(total=2),
                ) as resp:
                    mcp_connected = resp.status == 200
            except Exception:
                mcp_connected = False

        return web.json_response(
            {
                "status": "ok",
                "version": pkg_version,
                "uptime": round(time.time() - self._start_time, 1),
                "sessions": len(self.sessions),
                "backgroundTasks": len(self._background_tasks),
                "mcpServer": self.mcp_server_url or "not configured",
                "mcpConnected": mcp_connected,
            }
        )

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
            result = handler(**args) if args else handler()
            # Handle async handlers
            if asyncio.iscoroutine(result):
                result = await result
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
            result = handler(**args)
            # Handle async handlers
            if asyncio.iscoroutine(result):
                result = await result
            return web.json_response(result, headers=cors_headers)
        except Exception as e:
            logger.error(f"Action error ({action}): {e}")
            return web.json_response({"error": str(e)}, status=500, headers=cors_headers)

    def run(self) -> None:
        """Start the daemon (blocking)."""
        logger.info(f"Starting mcp-sideport on {self.host}:{self.port}")
        if self.mcp_server_url:
            logger.info(f"MCP Server: {self.mcp_server_url}")

        async def on_startup(app: web.Application) -> None:
            self.start_cleanup_task()

        async def on_cleanup(app: web.Application) -> None:
            await self.close()

        self.app.on_startup.append(on_startup)
        self.app.on_cleanup.append(on_cleanup)
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
