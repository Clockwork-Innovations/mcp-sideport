"""
MCP Sideport Daemon

MCP server using Streamable HTTP transport that serves browser UIs to AI coding tools.
Implements the MCP protocol with proper session management via Mcp-Session-Id header.
"""

import asyncio
import json
import logging
import os
import secrets
import time
import webbrowser
from pathlib import Path
from typing import Any, Callable, Optional
from uuid import uuid4

from aiohttp import web

logger = logging.getLogger("mcp_sideport")

# MCP Protocol version
MCP_PROTOCOL_VERSION = "2025-03-26"


class McpSession:
    """Represents an MCP protocol session with a client."""

    def __init__(self, session_id: str, client_info: dict | None = None):
        self.session_id = session_id
        self.client_info = client_info or {}
        self.created = time.time()
        self.initialized = False  # True after receiving 'initialized' notification
        self.last_activity = time.time()
        # App sessions launched by this MCP client
        self.app_sessions: list[str] = []

    def touch(self):
        """Update last activity timestamp."""
        self.last_activity = time.time()

    def to_dict(self) -> dict:
        return {
            "sessionId": self.session_id,
            "clientInfo": self.client_info,
            "created": self.created,
            "initialized": self.initialized,
            "lastActivity": self.last_activity,
            "appSessions": self.app_sessions,
        }


class SideportDaemon:
    """
    MCP server with Streamable HTTP transport for serving browser UIs.

    MCP Endpoints:
    - POST /mcp - JSON-RPC messages (requests, notifications, responses)
    - GET /mcp - SSE stream for server-initiated messages
    - DELETE /mcp - Terminate session

    App Endpoints:
    - POST /launch - Open browser with MCP App (via tools/call)
    - GET /app/{id} - Serve sandboxed host page
    - GET /dashboard - Direct dashboard access
    - GET /health - Health check
    """

    SERVER_INFO = {
        "name": "mcp-sideport",
        "version": "0.1.0",
    }

    CAPABILITIES = {
        "tools": {},
        "resources": {},
    }

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
            host: Host to bind to (127.0.0.1 for security)
            port: Port to listen on
            mcp_server_url: Upstream MCP server URL for fetching UI content
            auto_open_browser: Auto-open browser on launch tool
            action_handlers: Custom action handlers
            api_handlers: Custom GET API handlers
        """
        self.host = host
        self.port = port
        self.mcp_server_url = mcp_server_url or os.environ.get("MCP_SERVER_URL")
        self.auto_open_browser = auto_open_browser
        self.action_handlers = action_handlers or {}
        self.api_handlers = api_handlers or {}

        # MCP session storage: mcp_session_id -> McpSession
        self.mcp_sessions: dict[str, McpSession] = {}

        # App session storage: app_session_id -> app data
        self.app_sessions: dict[str, dict] = {}
        self.content_cache: dict[str, str] = {}

        # Upstream MCP connection cache
        self._upstream_cache: dict = {"html": None, "time": 0, "mcp_session_id": None}

        # JSON-RPC request ID counter
        self._request_id = 0

        self.app = self._create_app()

    def _create_app(self) -> web.Application:
        """Create aiohttp application with routes."""
        app = web.Application()

        # MCP protocol endpoint (Streamable HTTP transport)
        app.router.add_post("/mcp", self.handle_mcp_post)
        app.router.add_get("/mcp", self.handle_mcp_get)
        app.router.add_delete("/mcp", self.handle_mcp_delete)
        app.router.add_options("/mcp", self.handle_cors_preflight)

        # App routes (browser UI)
        app.router.add_get("/app/{session_id}", self.handle_app)
        app.router.add_get("/dashboard", self.handle_dashboard)
        app.router.add_get("/health", self.handle_health)

        # Legacy REST API routes (for browser-side calls)
        app.router.add_get("/api/{name}", self.handle_api_get)
        app.router.add_post("/api/action", self.handle_api_action)
        app.router.add_options("/api/action", self.handle_cors_preflight)

        return app

    def _generate_session_id(self) -> str:
        """Generate a cryptographically secure session ID."""
        return secrets.token_urlsafe(32)

    def _get_mcp_session(self, request: web.Request) -> McpSession | None:
        """Get MCP session from request header."""
        session_id = request.headers.get("Mcp-Session-Id")
        if session_id:
            session = self.mcp_sessions.get(session_id)
            if session:
                session.touch()
            return session
        return None

    def _require_session(self, request: web.Request) -> tuple[McpSession | None, web.Response | None]:
        """Require a valid MCP session, returning error response if invalid."""
        session_id = request.headers.get("Mcp-Session-Id")

        if not session_id:
            return None, web.json_response(
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Mcp-Session-Id header required"}},
                status=400,
            )

        session = self.mcp_sessions.get(session_id)
        if not session:
            return None, web.json_response(
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Session not found or terminated"}},
                status=404,
            )

        session.touch()
        return session, None

    async def handle_mcp_post(self, request: web.Request) -> web.Response:
        """
        POST /mcp - Handle JSON-RPC messages from MCP clients.

        Per MCP spec:
        - Requests return responses (with optional SSE stream)
        - Notifications return 202 Accepted
        - Session ID returned on initialize, required on subsequent requests
        """
        try:
            body = await request.json()
        except json.JSONDecodeError:
            return web.json_response(
                {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}},
                status=400,
            )

        # Handle batched messages
        if isinstance(body, list):
            return await self._handle_batch(request, body)

        # Single message
        return await self._handle_single_message(request, body)

    async def _handle_batch(self, request: web.Request, messages: list) -> web.Response:
        """Handle a batch of JSON-RPC messages."""
        responses = []
        for msg in messages:
            resp = await self._handle_single_message(request, msg, is_batch=True)
            if resp.status != 202:  # Not a notification
                resp_body = json.loads(resp.text)
                responses.append(resp_body)

        if not responses:
            return web.Response(status=202)

        return web.json_response(responses)

    async def _handle_single_message(
        self, request: web.Request, message: dict, is_batch: bool = False
    ) -> web.Response:
        """Handle a single JSON-RPC message."""
        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params", {})

        # Notification (no id) or Response (has result/error but no method)
        is_notification = msg_id is None and method is not None
        is_response = "result" in message or "error" in message

        if is_response:
            # Client sending response to server request - just acknowledge
            return web.Response(status=202)

        # Handle initialize specially - no session required
        if method == "initialize":
            return await self._handle_initialize(params, msg_id)

        # All other methods require a valid session
        session, error_response = self._require_session(request)
        if error_response:
            return error_response

        # Handle the method
        if method == "initialized":
            session.initialized = True
            logger.info(f"MCP session {session.session_id} initialized")
            return web.Response(status=202)

        # Dispatch to method handlers
        handler = self._get_method_handler(method)
        if not handler:
            if is_notification:
                return web.Response(status=202)
            return web.json_response({
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            })

        try:
            result = await handler(session, params)
            if is_notification:
                return web.Response(status=202)
            return web.json_response({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": result,
            })
        except Exception as e:
            logger.error(f"Error handling {method}: {e}")
            if is_notification:
                return web.Response(status=202)
            return web.json_response({
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32603, "message": str(e)},
            })

    async def _handle_initialize(self, params: dict, msg_id: Any) -> web.Response:
        """Handle the initialize request - creates a new MCP session."""
        client_info = params.get("clientInfo", {})
        protocol_version = params.get("protocolVersion")

        # Create new session
        session_id = self._generate_session_id()
        session = McpSession(session_id, client_info)
        self.mcp_sessions[session_id] = session

        logger.info(f"MCP session created: {session_id} for client {client_info.get('name', 'unknown')}")

        result = {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": self.CAPABILITIES,
            "serverInfo": self.SERVER_INFO,
        }

        response = web.json_response({
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": result,
        })
        # Return session ID in header per MCP spec
        response.headers["Mcp-Session-Id"] = session_id
        return response

    def _get_method_handler(self, method: str) -> Callable | None:
        """Get handler for an MCP method."""
        handlers = {
            "tools/list": self._handle_tools_list,
            "tools/call": self._handle_tools_call,
            "resources/list": self._handle_resources_list,
            "resources/read": self._handle_resources_read,
            "ping": self._handle_ping,
        }
        return handlers.get(method)

    async def _handle_ping(self, session: McpSession, params: dict) -> dict:
        """Handle ping request."""
        return {}

    async def _handle_tools_list(self, session: McpSession, params: dict) -> dict:
        """List available tools."""
        tools = [
            {
                "name": "launch_app",
                "description": "Launch a browser UI for the user",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "resourceUri": {
                            "type": "string",
                            "description": "URI of the UI resource to display (e.g., ui://dashboard/main)",
                        },
                        "title": {
                            "type": "string",
                            "description": "Window/tab title",
                        },
                    },
                    "required": ["resourceUri"],
                },
            },
            {
                "name": "get_sessions",
                "description": "List active app sessions for this client",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            },
        ]

        # Add custom action handlers as tools
        for name in self.action_handlers:
            tools.append({
                "name": f"action_{name}",
                "description": f"Execute action: {name}",
                "inputSchema": {"type": "object"},
            })

        return {"tools": tools}

    async def _handle_tools_call(self, session: McpSession, params: dict) -> dict:
        """Execute a tool call."""
        tool_name = params.get("name")
        arguments = params.get("arguments", {})

        if tool_name == "launch_app":
            return await self._tool_launch_app(session, arguments)
        elif tool_name == "get_sessions":
            return await self._tool_get_sessions(session, arguments)
        elif tool_name.startswith("action_"):
            action_name = tool_name[7:]  # Remove "action_" prefix
            return await self._tool_action(session, action_name, arguments)

        return {"content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}], "isError": True}

    async def _tool_launch_app(self, session: McpSession, args: dict) -> dict:
        """Launch a browser app session."""
        resource_uri = args.get("resourceUri")
        title = args.get("title", "MCP App")

        if not resource_uri:
            return {"content": [{"type": "text", "text": "resourceUri required"}], "isError": True}

        # Create app session linked to MCP session
        app_session_id = str(uuid4())
        self.app_sessions[app_session_id] = {
            "sessionId": app_session_id,
            "mcpSessionId": session.session_id,
            "resourceUri": resource_uri,
            "title": title,
            "created": time.time(),
            "status": "pending",
        }
        session.app_sessions.append(app_session_id)

        app_url = f"http://{self.host}:{self.port}/app/{app_session_id}"

        # Fetch content in background
        asyncio.create_task(self._fetch_content(app_session_id, resource_uri))

        # Open browser
        if self.auto_open_browser:
            try:
                webbrowser.open(app_url)
                logger.info(f"Opened browser for app {app_session_id} (MCP session: {session.session_id})")
            except Exception as e:
                logger.warning(f"Failed to open browser: {e}")

        return {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({
                        "sessionId": app_session_id,
                        "appUrl": app_url,
                        "status": "launched",
                    }),
                }
            ]
        }

    async def _tool_get_sessions(self, session: McpSession, args: dict) -> dict:
        """Get app sessions for this MCP client."""
        sessions = [
            self.app_sessions[sid]
            for sid in session.app_sessions
            if sid in self.app_sessions
        ]
        return {
            "content": [{"type": "text", "text": json.dumps({"sessions": sessions})}]
        }

    async def _tool_action(self, session: McpSession, action_name: str, args: dict) -> dict:
        """Execute a custom action."""
        handler = self.action_handlers.get(action_name)
        if not handler:
            return {"content": [{"type": "text", "text": f"Unknown action: {action_name}"}], "isError": True}

        try:
            if asyncio.iscoroutinefunction(handler):
                result = await handler(**args)
            else:
                result = handler(**args)
            return {"content": [{"type": "text", "text": json.dumps(result)}]}
        except Exception as e:
            return {"content": [{"type": "text", "text": str(e)}], "isError": True}

    async def _handle_resources_list(self, session: McpSession, params: dict) -> dict:
        """List available resources."""
        resources = [
            {
                "uri": "ui://dashboard/main",
                "name": "Dashboard",
                "mimeType": "text/html",
            }
        ]
        return {"resources": resources}

    async def _handle_resources_read(self, session: McpSession, params: dict) -> dict:
        """Read a resource."""
        uri = params.get("uri")

        if uri == "ui://dashboard/main":
            html = await self._get_dashboard_html()
            return {
                "contents": [{"uri": uri, "mimeType": "text/html", "text": html}]
            }

        return {"contents": []}

    async def handle_mcp_get(self, request: web.Request) -> web.Response:
        """
        GET /mcp - Open SSE stream for server-to-client messages.

        Per MCP spec, this allows the server to send requests/notifications to the client.
        """
        session, error_response = self._require_session(request)
        if error_response:
            return error_response

        # For now, return 405 - SSE streaming not yet implemented
        # Future: implement SSE for server-initiated messages
        return web.Response(status=405, text="SSE streaming not yet supported")

    async def handle_mcp_delete(self, request: web.Request) -> web.Response:
        """
        DELETE /mcp - Terminate MCP session.

        Per MCP spec, clients should call this when done.
        """
        session_id = request.headers.get("Mcp-Session-Id")

        if not session_id:
            return web.Response(status=400, text="Mcp-Session-Id header required")

        session = self.mcp_sessions.pop(session_id, None)
        if not session:
            return web.Response(status=404, text="Session not found")

        # Clean up app sessions belonging to this MCP session
        for app_sid in session.app_sessions:
            self.app_sessions.pop(app_sid, None)
            self.content_cache.pop(app_sid, None)

        logger.info(f"MCP session terminated: {session_id}")
        return web.Response(status=204)

    # ---- App serving endpoints ----

    async def _fetch_content(self, app_session_id: str, resource_uri: str) -> None:
        """Fetch content from upstream MCP server or use placeholder."""
        self.content_cache[app_session_id] = self._loading_html(resource_uri)

        if self.mcp_server_url:
            try:
                html = await self._fetch_from_upstream_mcp(resource_uri)
                if html:
                    self.content_cache[app_session_id] = html
                    if app_session_id in self.app_sessions:
                        self.app_sessions[app_session_id]["status"] = "ready"
                    return
            except Exception as e:
                logger.warning(f"Failed to fetch from upstream MCP: {e}")
                if app_session_id in self.app_sessions:
                    self.app_sessions[app_session_id]["status"] = "error"
                    self.app_sessions[app_session_id]["error"] = str(e)

    async def _fetch_from_upstream_mcp(self, resource_uri: str) -> Optional[str]:
        """Fetch HTML from upstream MCP server."""
        import aiohttp

        async with aiohttp.ClientSession() as http_session:
            mcp_session_id = self._upstream_cache.get("mcp_session_id")

            if not mcp_session_id:
                # Initialize upstream MCP session
                init_resp = await http_session.post(
                    f"{self.mcp_server_url}/mcp",
                    json={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": MCP_PROTOCOL_VERSION,
                            "capabilities": {},
                            "clientInfo": self.SERVER_INFO,
                        },
                    },
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream",
                    },
                )
                mcp_session_id = init_resp.headers.get("Mcp-Session-Id")
                self._upstream_cache["mcp_session_id"] = mcp_session_id

            if mcp_session_id:
                res_resp = await http_session.post(
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

                # Parse SSE or JSON response
                for line in text.split("\n"):
                    if line.startswith("data: "):
                        data = json.loads(line[6:])
                        if "result" in data and "contents" in data["result"]:
                            return data["result"]["contents"][0].get("text", "")

                # Try direct JSON
                try:
                    data = json.loads(text)
                    if "result" in data and "contents" in data["result"]:
                        return data["result"]["contents"][0].get("text", "")
                except json.JSONDecodeError:
                    pass

        return None

    def _loading_html(self, resource_uri: str) -> str:
        """Generate loading placeholder HTML."""
        # Escape resource_uri for safe HTML embedding
        safe_uri = resource_uri.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        return f"""<!DOCTYPE html>
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
</html>"""

    async def _get_dashboard_html(self) -> str:
        """Get dashboard HTML (cached or from file)."""
        static_file = Path(__file__).parent / "static" / "dashboard.html"
        if static_file.exists():
            return static_file.read_text()

        return """<!DOCTYPE html>
<html>
<head><title>MCP Sideport Dashboard</title></head>
<body>
    <h1>MCP Sideport</h1>
    <p>No dashboard configured. Create static/dashboard.html</p>
</body>
</html>"""

    async def handle_app(self, request: web.Request) -> web.Response:
        """GET /app/{session_id} - Serve sandboxed app page."""
        app_session_id = request.match_info["session_id"]
        app_session = self.app_sessions.get(app_session_id)

        if not app_session:
            return web.Response(text="Session not found", status=404)

        content = self.content_cache.get(app_session_id, "<p>Loading...</p>")

        return web.Response(
            text=content,
            content_type="text/html",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )

    async def handle_dashboard(self, request: web.Request) -> web.Response:
        """GET /dashboard - Direct dashboard access."""
        html = await self._get_dashboard_html()
        return web.Response(
            text=html,
            content_type="text/html",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate"},
        )

    async def handle_health(self, request: web.Request) -> web.Response:
        """GET /health - Health check."""
        return web.json_response({
            "status": "ok",
            "mcpSessions": len(self.mcp_sessions),
            "appSessions": len(self.app_sessions),
            "upstreamMcp": self.mcp_server_url or "not configured",
            "protocolVersion": MCP_PROTOCOL_VERSION,
        })

    async def handle_cors_preflight(self, request: web.Request) -> web.Response:
        """Handle CORS preflight."""
        return web.Response(
            status=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, Mcp-Session-Id",
            },
        )

    # ---- Legacy REST API (for browser-side calls) ----

    def register_action(self, name: str, handler: Callable) -> None:
        """Register a custom action handler."""
        self.action_handlers[name] = handler

    def register_api(self, name: str, handler: Callable) -> None:
        """Register a custom GET API handler."""
        self.api_handlers[name] = handler

    async def handle_api_get(self, request: web.Request) -> web.Response:
        """GET /api/{name} - Custom API handlers (for browser-side calls)."""
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
            if asyncio.iscoroutinefunction(handler):
                result = await handler(**args) if args else await handler()
            else:
                result = handler(**args) if args else handler()
            return web.json_response(result, headers=cors_headers)
        except Exception as e:
            logger.error(f"API error ({name}): {e}")
            return web.json_response({"error": str(e)}, status=500, headers=cors_headers)

    async def handle_api_action(self, request: web.Request) -> web.Response:
        """POST /api/action - Execute actions (for browser-side calls)."""
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
        logger.info(f"MCP endpoint: http://{self.host}:{self.port}/mcp")
        if self.mcp_server_url:
            logger.info(f"Upstream MCP Server: {self.mcp_server_url}")
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
        description="mcp-sideport - MCP server for browser UIs in AI coding tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  mcp-sideport --port 3847
  mcp-sideport --mcp-server http://127.0.0.1:3850  # upstream UI server
  uvx mcp-sideport --help

MCP clients connect to http://127.0.0.1:3847/mcp
        """,
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=3847, help="Port to listen on")
    parser.add_argument("--mcp-server", help="Upstream MCP server URL for UI content")
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
