# mcp-sideport

MCP Apps bridge for AI coding tools. Enables browser UIs (MCP Apps) in CLI-based AI assistants with REST API fallback.

## Quick Start

```bash
# Run directly with uvx (no install needed)
uvx mcp-sideport --port 3847 --mcp-server http://127.0.0.1:3850

# Or install permanently
pip install mcp-sideport
mcp-sideport --help
```

## What It Does

When an MCP server returns a `ui://` resource (an MCP App), mcp-sideport:

1. Fetches the HTML from the MCP server
2. Opens it in your browser
3. Provides REST endpoints as fallback for `window.mcpApps.callTool()`

This bridges the gap between MCP Apps and CLI-based AI tools that don't implement the MCP Apps host spec.

## The Problem

**MCP Apps** extends MCP to allow servers to return rich browser UIs (`ui://` resources). The MCP client is supposed to:
1. Render the HTML in a sandboxed browser
2. Inject `window.mcpApps` bridge for tool communication
3. Handle `callTool()` requests from the UI back to the MCP server

CLI-based AI tools implement MCP transport but often not the MCP Apps host. When a tool returns `ui://`, nothing renders.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Without mcp-sideport                                               │
│                                                                     │
│  MCP Server ──► ui://dashboard/main ──► AI Tool ──► ??? (dropped)   │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│  With mcp-sideport                                                  │
│                                                                     │
│  MCP Server ──► ui://... ──► Sideport ──► Browser ──► REST fallback │
│       ▲                                                     │       │
│       └─────────────── /api/* endpoints ◄───────────────────┘       │
└─────────────────────────────────────────────────────────────────────┘
```

## Usage

### CLI

```bash
# Basic usage
mcp-sideport --port 3847 --mcp-server http://127.0.0.1:3850

# With environment variable
MCP_SERVER_URL=http://127.0.0.1:3850 mcp-sideport

# Don't auto-open browser
mcp-sideport --no-browser --mcp-server http://127.0.0.1:3850
```

### Python API

```python
from mcp_sideport import SideportDaemon

daemon = SideportDaemon(
    port=3847,
    mcp_server_url="http://127.0.0.1:3850",
)

# Register custom API endpoints
daemon.register_api("sessions", lambda: {"sessions": get_sessions()})
daemon.register_api("tasks", lambda project: {"tasks": get_tasks(project)})

# Register custom actions
daemon.register_action("spawn", lambda project: spawn_session(project))

daemon.run()
```

### Hybrid API for MCP Apps

Include the hybrid API script in your MCP App HTML to work in both native MCP Apps hosts and via mcp-sideport:

```python
from mcp_sideport import generate_hybrid_api_script

js = generate_hybrid_api_script(
    api_base="http://127.0.0.1:3847",
    enable_hmr=True,
)
```

Then in your HTML:

```html
<script>
  // Generated hybrid API code here...

  // Works in both MCP Apps host and via sideport
  const sessions = await callToolOrApi('getSessions', {}, '/api/sessions');
</script>
```

## Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/launch` | POST | Open browser with `{"resourceUri": "ui://..."}` |
| `/dashboard` | GET | Direct dashboard access (fetches from MCP server) |
| `/app/{id}` | GET | Session-based app page |
| `/api/{name}` | GET | Custom read handlers |
| `/api/action` | POST | Custom write handlers |
| `/health` | GET | Health check with uptime, version, MCP status |

## Configuration

### Request Body Size Limit

Default: **5MB** - balances security with usability for JSON + base64 thumbnails.

```python
# For media uploads, increase the limit:
daemon = SideportDaemon(
    client_max_size=50 * 1024 * 1024,  # 50MB
)
```

### Session TTL

Default: **1 hour**. Sessions are automatically cleaned up after expiry.

```python
daemon = SideportDaemon(
    session_ttl=7200,  # 2 hours
)
```

### All Options

```python
SideportDaemon(
    host="127.0.0.1",           # Bind address
    port=3847,                   # Listen port
    mcp_server_url="...",        # Upstream MCP server (enables HMR)
    auto_open_browser=True,      # Open browser on /launch
    session_ttl=3600,            # Session TTL in seconds
    client_max_size=5*1024*1024, # Max request body (bytes)
)
```

## Future Compatibility

When AI coding tools add native MCP Apps support:
- The `hasMcpBridge()` check will return `true`
- `window.mcpApps.callTool()` will work natively
- REST fallback becomes unused (but harmless)
- **No code changes needed** - same HTML works both ways

## License

MIT
