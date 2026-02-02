"""
MCP Sideport Daemon

MCP server using Streamable HTTP transport that serves browser UIs to AI coding tools.
Maintains state for SSE connections to route messages from browser UIs back to MCP clients.
"""

import asyncio
import base64
import hashlib
import hmac
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

# MCP Protocol version
MCP_PROTOCOL_VERSION = "2025-03-26"

# Secret for signing session tokens
_SESSION_SECRET = os.environ.get("MCP_SESSION_SECRET", os.urandom(32).hex())


def _encode_session_token(data: dict) -> str:
    """Encode session data into a signed token for the Mcp-Session-Id header."""
    payload = base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    sig = hmac.new(_SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{payload}.{sig}"


def _decode_session_token(token: str) -> dict | None:
    """Decode and verify a session token."""
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None

        payload, sig = parts
        expected_sig = hmac.new(_SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]

        if not hmac.compare_digest(sig, expected_sig):
            logger.warning("Invalid session token signature")
            return None

        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding

        return json.loads(base64.urlsafe_b64decode(payload).decode())
    except Exception as e:
        logger.warning(f"Failed to decode session token: {e}")
        return None


class McpSession:
    """
    Active MCP session state.

    Required for:
    - SSE connection to send server-initiated messages to client
    - Routing messages from browser UIs back to the correct client
    - Tracking pending requests for progress/cancellation
    """

    def __init__(self, session_id: str, agent_id: str | None, client_info: dict):
        self.session_id = session_id
        self.agent_id = agent_id
        self.client_info = client_info
        self.created = time.time()
        self.last_activity = time.time()
        self.initialized = False

        # SSE message queue for server-to-client messages
        self.sse_queue: asyncio.Queue = asyncio.Queue()

        # Active SSE connections (can have multiple per session)
        self.sse_connections: list[web.StreamResponse] = []

        # App sessions launched by this MCP client
        self.app_sessions: list[str] = []

        # Pending requests (for progress tracking)
        self.pending_requests: dict[Any, dict] = {}

    def touch(self):
        self.last_activity = time.time()

    async def send_to_client(self, message: dict) -> bool:
        """Send a JSON-RPC message to the client via SSE."""
        if not self.sse_connections:
            logger.warning(f"No SSE connection for session {self.session_id}")
            return False

        data = f"data: {json.dumps(message)}\n\n"
        for conn in self.sse_connections:
            try:
                await conn.write(data.encode())
            except Exception as e:
                logger.warning(f"Failed to write to SSE: {e}")
        return True

    def to_dict(self) -> dict:
        return {
            "sessionId": self.session_id,
            "agentId": self.agent_id,
            "clientInfo": self.client_info,
            "created": self.created,
            "lastActivity": self.last_activity,
            "initialized": self.initialized,
            "hasSSE": len(self.sse_connections) > 0,
            "appSessions": self.app_sessions,
        }


class SideportDaemon:
    """
    MCP server with Streamable HTTP transport for serving browser UIs.

    State Management:
    - MCP sessions: Track active clients with SSE connections for bidirectional communication
    - App sessions: Map browser UIs to their owning MCP client for routing

    MCP Endpoints:
    - POST /mcp - JSON-RPC requests/notifications from client
    - GET /mcp - SSE stream for server-to-client messages
    - DELETE /mcp - Session termination

    App Endpoints:
    - GET /app/{id} - Serve browser UI
    - POST /app/{id}/message - Browser UI sends message to its MCP client
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
        self.host = host
        self.port = port
        self.mcp_server_url = mcp_server_url or os.environ.get("MCP_SERVER_URL")
        self.auto_open_browser = auto_open_browser
        self.action_handlers = action_handlers or {}
        self.api_handlers = api_handlers or {}

        # MCP session state: session_id -> McpSession
        # Required for SSE connections and routing
        self.mcp_sessions: dict[str, McpSession] = {}

        # App session state: app_session_id -> app data
        # Includes mcp_session_id for routing back to client
        self.app_sessions: dict[str, dict] = {}
        self.content_cache: dict[str, str] = {}

        # Upstream MCP connection cache
        self._upstream_cache: dict = {"mcp_session_id": None}

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
        app.router.add_post("/app/{session_id}/message", self.handle_app_message)
        app.router.add_options("/app/{session_id}/message", self.handle_cors_preflight)
        app.router.add_get("/dashboard", self.handle_dashboard)
        app.router.add_get("/health", self.handle_health)

        # Query endpoints
        app.router.add_get("/apps", self.handle_list_apps)
        app.router.add_get("/sessions", self.handle_list_sessions)
        app.router.add_delete("/apps/{session_id}", self.handle_delete_app)
        app.router.add_options("/apps/{session_id}", self.handle_cors_preflight)

        # Legacy REST API routes (for browser-side calls)
        app.router.add_get("/api/{name}", self.handle_api_get)
        app.router.add_post("/api/action", self.handle_api_action)
        app.router.add_options("/api/action", self.handle_cors_preflight)

        return app

    # ---- MCP Protocol Handlers ----

    async def handle_mcp_post(self, request: web.Request) -> web.Response:
        """
        POST /mcp - Handle JSON-RPC messages.

        Session ID header contains signed token with routing info.
        Server is stateless - just decode token to get context.
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

        return await self._handle_single_message(request, body)

    async def _handle_batch(self, request: web.Request, messages: list) -> web.Response:
        """Handle a batch of JSON-RPC messages."""
        responses = []
        for msg in messages:
            resp = await self._handle_single_message(request, msg, is_batch=True)
            if resp.status != 202:
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

        is_notification = msg_id is None and method is not None
        is_response = "result" in message or "error" in message

        if is_response:
            return web.Response(status=202)

        # Initialize - creates new session token
        if method == "initialize":
            return await self._handle_initialize(params, msg_id)

        # All other methods require valid session
        session_token = request.headers.get("Mcp-Session-Id")
        if not session_token:
            return web.json_response(
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Mcp-Session-Id header required"}},
                status=400,
            )

        # Look up session state
        session = self.mcp_sessions.get(session_token)
        if not session:
            # Try to validate token (session might have been created but not stored)
            token_data = _decode_session_token(session_token)
            if not token_data:
                return web.json_response(
                    {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid or expired session"}},
                    status=404,
                )
            # Token valid but session not found (terminated)
            return web.json_response(
                {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Session terminated"}},
                status=404,
            )

        session.touch()

        # Handle initialized notification
        if method == "initialized":
            session.initialized = True
            logger.info(f"MCP session initialized for agent: {session.agent_id or 'anonymous'}")
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
            # Pass decoded session context to handler
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
        """
        Handle initialize request.

        Creates session state for SSE routing and a signed token for the header.
        """
        client_info = params.get("clientInfo", {})
        agent_id = client_info.get("agentId")

        # Create session token (signed, for header)
        session_data = {
            "agentId": agent_id,
            "clientName": client_info.get("name", "unknown"),
            "clientVersion": client_info.get("version", "0.0.0"),
            "created": time.time(),
        }
        session_token = _encode_session_token(session_data)

        # Create session state (for SSE connections and routing)
        session = McpSession(session_token, agent_id, client_info)
        self.mcp_sessions[session_token] = session

        logger.info(
            f"MCP session created: {session_token[:20]}... "
            f"for client {client_info.get('name', 'unknown')} "
            f"(agent: {agent_id or 'anonymous'})"
        )

        response = web.json_response({
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": self.CAPABILITIES,
                "serverInfo": self.SERVER_INFO,
            },
        })
        response.headers["Mcp-Session-Id"] = session_token
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
                            "description": "URI of the UI resource (e.g., ui://dashboard/main)",
                        },
                        "title": {"type": "string", "description": "Window/tab title"},
                    },
                    "required": ["resourceUri"],
                },
            },
            {
                "name": "list_apps",
                "description": "List active app sessions for this agent",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "close_app",
                "description": "Close an app session",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "appSessionId": {"type": "string", "description": "The app session ID to close"},
                    },
                    "required": ["appSessionId"],
                },
            },
        ]

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
        elif tool_name == "list_apps":
            return await self._tool_list_apps(session, arguments)
        elif tool_name == "close_app":
            return await self._tool_close_app(session, arguments)
        elif tool_name and tool_name.startswith("action_"):
            action_name = tool_name[7:]
            return await self._tool_action(session, action_name, arguments)

        return {"content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}], "isError": True}

    async def _tool_launch_app(self, session: McpSession, args: dict) -> dict:
        """Launch a browser app session linked to this MCP session."""
        resource_uri = args.get("resourceUri")
        title = args.get("title", "MCP App")

        if not resource_uri:
            return {"content": [{"type": "text", "text": "resourceUri required"}], "isError": True}

        # Create app session linked to MCP session for routing
        app_session_id = str(uuid4())
        self.app_sessions[app_session_id] = {
            "sessionId": app_session_id,
            "mcpSessionId": session.session_id,  # Link to MCP session for routing
            "agentId": session.agent_id,
            "resourceUri": resource_uri,
            "title": title,
            "created": time.time(),
            "status": "pending",
        }

        # Track in MCP session
        session.app_sessions.append(app_session_id)

        app_url = f"http://{self.host}:{self.port}/app/{app_session_id}"

        # Fetch content in background
        asyncio.create_task(self._fetch_content(app_session_id, resource_uri))

        if self.auto_open_browser:
            try:
                webbrowser.open(app_url)
                logger.info(f"Opened browser for app {app_session_id} (agent: {session.agent_id})")
            except Exception as e:
                logger.warning(f"Failed to open browser: {e}")

        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "sessionId": app_session_id,
                    "appUrl": app_url,
                    "status": "launched",
                }),
            }]
        }

    async def _tool_list_apps(self, session: McpSession, args: dict) -> dict:
        """List app sessions for this MCP session."""
        apps = [
            self.app_sessions[sid]
            for sid in session.app_sessions
            if sid in self.app_sessions
        ]

        return {
            "content": [{
                "type": "text",
                "text": json.dumps({
                    "mcpSessionId": session.session_id[:20] + "...",
                    "agentId": session.agent_id,
                    "apps": apps,
                }),
            }]
        }

    async def _tool_close_app(self, session: McpSession, args: dict) -> dict:
        """Close an app session."""
        app_session_id = args.get("appSessionId")

        if not app_session_id:
            return {"content": [{"type": "text", "text": "appSessionId required"}], "isError": True}

        app = self.app_sessions.get(app_session_id)
        if not app:
            return {"content": [{"type": "text", "text": f"App not found: {app_session_id}"}], "isError": True}

        # Verify ownership
        if app.get("mcpSessionId") != session.session_id:
            return {"content": [{"type": "text", "text": "Cannot close app owned by different session"}], "isError": True}

        # Remove from session tracking
        session.app_sessions = [sid for sid in session.app_sessions if sid != app_session_id]

        # Remove app session
        del self.app_sessions[app_session_id]
        self.content_cache.pop(app_session_id, None)

        return {
            "content": [{
                "type": "text",
                "text": json.dumps({"status": "closed", "sessionId": app_session_id}),
            }]
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
        return {
            "resources": [{
                "uri": "ui://dashboard/main",
                "name": "Dashboard",
                "mimeType": "text/html",
            }]
        }

    async def _handle_resources_read(self, session: McpSession, params: dict) -> dict:
        """Read a resource."""
        uri = params.get("uri")

        if uri == "ui://dashboard/main":
            html = await self._get_dashboard_html()
            return {"contents": [{"uri": uri, "mimeType": "text/html", "text": html}]}

        return {"contents": []}

    async def handle_mcp_get(self, request: web.Request) -> web.Response:
        """
        GET /mcp - SSE stream for server-to-client messages.

        Keeps connection open so server can send notifications/requests to client.
        Required for routing messages from browser UIs back to the MCP client.
        """
        session_token = request.headers.get("Mcp-Session-Id")
        if not session_token:
            return web.Response(status=400, text="Mcp-Session-Id header required")

        session = self.mcp_sessions.get(session_token)
        if not session:
            return web.Response(status=404, text="Session not found")

        # Create SSE response
        response = web.StreamResponse(
            status=200,
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Access-Control-Allow-Origin": "*",
            },
        )
        await response.prepare(request)

        # Register this SSE connection
        session.sse_connections.append(response)
        logger.info(f"SSE connection opened for session {session_token[:20]}...")

        try:
            # Keep connection alive, send heartbeat every 30s
            while True:
                try:
                    # Check if there are messages to send
                    try:
                        message = await asyncio.wait_for(session.sse_queue.get(), timeout=30.0)
                        await response.write(f"data: {json.dumps(message)}\n\n".encode())
                    except asyncio.TimeoutError:
                        # Send heartbeat comment
                        await response.write(b": heartbeat\n\n")
                except ConnectionResetError:
                    break
        finally:
            # Unregister SSE connection
            session.sse_connections = [c for c in session.sse_connections if c != response]
            logger.info(f"SSE connection closed for session {session_token[:20]}...")

        return response

    async def handle_mcp_delete(self, request: web.Request) -> web.Response:
        """
        DELETE /mcp - Terminate MCP session.

        Cleans up session state, SSE connections, and app sessions.
        """
        session_token = request.headers.get("Mcp-Session-Id")
        if not session_token:
            return web.Response(status=400, text="Mcp-Session-Id header required")

        session = self.mcp_sessions.pop(session_token, None)
        if not session:
            return web.Response(status=404, text="Session not found")

        # Close SSE connections
        for conn in session.sse_connections:
            try:
                await conn.write_eof()
            except Exception:
                pass

        # Clean up app sessions
        for app_sid in session.app_sessions:
            self.app_sessions.pop(app_sid, None)
            self.content_cache.pop(app_sid, None)

        logger.info(
            f"MCP session terminated: {session_token[:20]}... "
            f"(agent: {session.agent_id or 'anonymous'}, "
            f"apps: {len(session.app_sessions)})"
        )
        return web.Response(status=204)

    # ---- App Session Endpoints ----

    async def handle_app_message(self, request: web.Request) -> web.Response:
        """
        POST /app/{session_id}/message - Browser UI sends message to its MCP client.

        Routes the message through the SSE connection to the owning MCP client.
        This enables bidirectional communication: Browser UI -> Sideport -> MCP Client.
        """
        cors_headers = {"Access-Control-Allow-Origin": "*"}
        app_session_id = request.match_info["session_id"]

        app = self.app_sessions.get(app_session_id)
        if not app:
            return web.json_response({"error": "App not found"}, status=404, headers=cors_headers)

        # Get the MCP session for routing
        mcp_session_id = app.get("mcpSessionId")
        mcp_session = self.mcp_sessions.get(mcp_session_id) if mcp_session_id else None

        if not mcp_session:
            return web.json_response(
                {"error": "MCP session not found - client may have disconnected"},
                status=404,
                headers=cors_headers,
            )

        try:
            data = await request.json()
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400, headers=cors_headers)

        # Queue message for delivery via SSE
        message = {
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {
                "appSessionId": app_session_id,
                "agentId": app.get("agentId"),
                "data": data,
            },
        }

        if mcp_session.sse_connections:
            await mcp_session.send_to_client(message)
            return web.json_response({"status": "sent"}, headers=cors_headers)
        else:
            # Queue for later if no active SSE connection
            await mcp_session.sse_queue.put(message)
            return web.json_response({"status": "queued"}, headers=cors_headers)

    async def handle_list_apps(self, request: web.Request) -> web.Response:
        """GET /apps - List app sessions, optionally filtered by agentId."""
        cors_headers = {"Access-Control-Allow-Origin": "*"}
        agent_id = request.query.get("agentId")

        if agent_id:
            apps = [app for app in self.app_sessions.values() if app.get("agentId") == agent_id]
        else:
            apps = list(self.app_sessions.values())

        return web.json_response({"apps": apps}, headers=cors_headers)

    async def handle_list_sessions(self, request: web.Request) -> web.Response:
        """GET /sessions - List active MCP sessions."""
        cors_headers = {"Access-Control-Allow-Origin": "*"}

        sessions = [session.to_dict() for session in self.mcp_sessions.values()]
        return web.json_response({"sessions": sessions}, headers=cors_headers)

    async def handle_delete_app(self, request: web.Request) -> web.Response:
        """DELETE /apps/{session_id} - Close an app session."""
        cors_headers = {"Access-Control-Allow-Origin": "*"}
        app_session_id = request.match_info["session_id"]

        app = self.app_sessions.get(app_session_id)
        if not app:
            return web.json_response({"error": "App not found"}, status=404, headers=cors_headers)

        # Remove from owning MCP session
        mcp_session_id = app.get("mcpSessionId")
        if mcp_session_id and mcp_session_id in self.mcp_sessions:
            mcp_session = self.mcp_sessions[mcp_session_id]
            mcp_session.app_sessions = [sid for sid in mcp_session.app_sessions if sid != app_session_id]

        del self.app_sessions[app_session_id]
        self.content_cache.pop(app_session_id, None)

        return web.json_response({"status": "closed", "sessionId": app_session_id}, headers=cors_headers)

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

                for line in text.split("\n"):
                    if line.startswith("data: "):
                        data = json.loads(line[6:])
                        if "result" in data and "contents" in data["result"]:
                            return data["result"]["contents"][0].get("text", "")

                try:
                    data = json.loads(text)
                    if "result" in data and "contents" in data["result"]:
                        return data["result"]["contents"][0].get("text", "")
                except json.JSONDecodeError:
                    pass

        return None

    def _loading_html(self, resource_uri: str) -> str:
        """Generate loading placeholder HTML."""
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
        """Get dashboard HTML."""
        static_file = Path(__file__).parent / "static" / "dashboard.html"
        if static_file.exists():
            return static_file.read_text()

        return """<!DOCTYPE html>
<html>
<head><title>MCP Sideport Dashboard</title></head>
<body>
    <h1>MCP Sideport</h1>
    <p>No dashboard configured.</p>
</body>
</html>"""

    async def handle_app(self, request: web.Request) -> web.Response:
        """GET /app/{session_id} - Serve browser UI."""
        session_id = request.match_info["session_id"]

        if session_id not in self.app_sessions:
            return web.Response(text="Session not found", status=404)

        content = self.content_cache.get(session_id, "<p>Loading...</p>")

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
        sse_count = sum(len(s.sse_connections) for s in self.mcp_sessions.values())
        return web.json_response({
            "status": "ok",
            "mcpSessions": len(self.mcp_sessions),
            "sseConnections": sse_count,
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

    # ---- Legacy REST API ----

    def register_action(self, name: str, handler: Callable) -> None:
        """Register a custom action handler."""
        self.action_handlers[name] = handler

    def register_api(self, name: str, handler: Callable) -> None:
        """Register a custom GET API handler."""
        self.api_handlers[name] = handler

    async def handle_api_get(self, request: web.Request) -> web.Response:
        """GET /api/{name} - Custom API handlers."""
        name = request.match_info["name"]
        cors_headers = {"Access-Control-Allow-Origin": "*"}

        handler = self.api_handlers.get(name)
        if not handler:
            return web.json_response({"error": f"Unknown API: {name}"}, status=404, headers=cors_headers)

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
            return web.json_response({"error": f"Unknown action: {action}"}, status=400, headers=cors_headers)

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
            logger.info(f"Upstream MCP: {self.mcp_server_url}")
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
  mcp-sideport --mcp-server http://127.0.0.1:3850

MCP clients connect to http://127.0.0.1:3847/mcp
        """,
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=3847, help="Port to listen on")
    parser.add_argument("--mcp-server", help="Upstream MCP server URL")
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
