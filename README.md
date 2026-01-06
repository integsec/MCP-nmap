# MCP Discovery NSE Script for Nmap

An Nmap Scripting Engine (NSE) script that discovers Model Context Protocol (MCP) endpoints by probing HTTP, SSE, and WebSocket services with JSON-RPC 2.0 requests.

**Developed by [IntegSec](https://integsec.com)**

## What is MCP?

The Model Context Protocol (MCP) is an open protocol that enables AI assistants to securely access tools, resources, and prompts from external servers. This script helps identify MCP-enabled services on a network.

## Features

- **Full Transport Support**: Discovers MCP endpoints using all three transport methods:
  - **HTTP (Streamable HTTP)** - The 2025 standard transport
  - **SSE (Server-Sent Events)** - Legacy transport (pre-2025)
  - **WebSocket** - Real-time bidirectional communication
- **Automatic Transport Detection**: Intelligently detects and uses the correct transport based on path
- **Comprehensive Path Coverage**: Tests 27+ common MCP paths including gateways, proxies, and framework-specific endpoints
- **Full MCP Protocol Support**: Properly implements MCP protocol flow (initialize → list methods)
- **Authentication Support**: Detects Bearer token authentication and can optionally brute force with common credentials
- **Detailed Enumeration**: Lists actual tools, resources, and prompts (not just counts)
- **Server Fingerprinting**: Extracts server name, version, protocol version, and capabilities
- **Safe by Default**: Non-intrusive scanning with opt-in brute force
- **Customizable**: Custom paths, timeouts, and credential lists

## Installation

### Option 1: Copy to Nmap scripts directory

1. Locate your Nmap scripts directory:
   ```bash
   # Linux/Mac
   nmap --script-updatedb
   ls /usr/share/nmap/scripts/

   # Windows
   # Usually: C:\Program Files (x86)\Nmap\scripts\
   ```

2. Copy the script:
   ```bash
   # Linux/Mac
   sudo cp mcp-discovery.nse /usr/share/nmap/scripts/

   # Windows (as Administrator)
   copy mcp-discovery.nse "C:\Program Files (x86)\Nmap\scripts\"
   ```

3. Update the script database:
   ```bash
   nmap --script-updatedb
   ```

### Option 2: Run from current directory

You can run the script directly from the current directory without installation:

```bash
nmap --script ./mcp-discovery.nse <target>
```

## Usage

**⚠️ IMPORTANT:** This script requires service detection (`-sV`) to work properly. It uses Nmap's service detection to identify HTTP/HTTPS services on any port, which means it will find MCP endpoints regardless of port number.

### Basic Scan

Scan a single host on common web ports with service detection:

```bash
nmap -p 80,443,3000-3100 -sV --script mcp-discovery <target>
```

### Scan All Ports

Scan all ports for MCP endpoints (this will find HTTP services on any port):

```bash
nmap -p- -sV --script mcp-discovery <target>
```

### Scan Multiple Hosts

Scan a network range:

```bash
nmap -p 80,443,3000-3100 -sV --script mcp-discovery 192.168.1.0/24
```

### Scan from File

Scan hosts listed in a file:

```bash
nmap -p 80,443,3000-3100 -sV --script mcp-discovery -iL targets.txt
```

### Additional Custom Paths

Add additional paths to probe (the 27 default paths are always tested):

```bash
nmap -p 80,443 -sV --script mcp-discovery --script-args mcp-discovery.paths=/api/v2/mcp,/custom/endpoint <target>
```

**Note:** The script always tests all 27 default paths (including `/mcp`, `/sse`, `/ws`, etc.). This argument lets you add MORE paths on top of the defaults.

### Adjust Timeout

Set a custom timeout (default is 5000ms):

```bash
nmap -p 80,443 -sV --script mcp-discovery --script-args mcp-discovery.timeout=10000 <target>
```

### Verbose Output

Get more detailed information:

```bash
nmap -p 80,443 -sV --script mcp-discovery -v <target>
```

### Debug Mode

Enable debug output for troubleshooting:

```bash
nmap -p 80,443 -sV --script mcp-discovery -d <target>
```

### Brute Force Authentication

When encountering authenticated MCP endpoints (like MCP Gateway), enable brute force to attempt common tokens:

```bash
nmap -p 8811 -sV --script mcp-discovery --script-args mcp-discovery.bruteforce=true <target>
```

Use custom password database:

```bash
nmap -p 8811 -sV --script mcp-discovery --script-args mcp-discovery.bruteforce=true,mcp-discovery.passdb=/path/to/tokens.txt <target>
```

The script automatically tries:
- Common development tokens (`dev`, `test`, `admin`)
- Default MCP Gateway tokens (`mcp`, `mcpgateway`, `gateway`)
- Common weak passwords (`password`, `changeme`, `secret`)
- Empty/null tokens
- Custom tokens from provided database

## Output Examples

### Successful MCP Discovery (HTTP Transport)

```
PORT     STATE SERVICE
3000/tcp open  ppp
| mcp-discovery:
|   endpoints:
|     [1]
|       url: http://192.168.1.100:3000/mcp
|       protocol: HTTP
|       transport: HTTP
|       methods:
|         initialize: Initialized successfully
|         tools/list: 3 tools available
|         resources/list: 5 resources available
|         prompts/list: 2 prompts available
|       server_info:
|         name: example-mcp-server
|         version: 1.0.0
|         protocolVersion: 2024-11-05
|       tools:
|         read_file: Read contents of a file
|         write_file: Write content to a file
|         execute_command: Execute a shell command
|       resources:
|         file:///home/user/docs: Project documentation (text/markdown)
|         file:///home/user/data: Data directory (application/x-directory)
|         config://app: Application configuration
|         database://main: Main database connection
|         cache://redis: Redis cache instance
|       prompts:
|         code_review: Review code for best practices
|_        bug_analysis: Analyze bugs and suggest fixes
```

### SSE Transport Discovery (Legacy Pre-2025)

```
PORT     STATE SERVICE
3000/tcp open  ppp
| mcp-discovery:
|   endpoints:
|     [1]
|       url: http://192.168.1.100:3000/sse
|       protocol: HTTP
|       transport: SSE
|       methods:
|         initialize: Initialized successfully
|         tools/list: 2 tools available
|       server_info:
|         name: legacy-mcp-server
|         protocolVersion: 2024-10-01
|       tools:
|         search: Search for information
|_        summarize: Summarize text content
```

### WebSocket Transport Discovery

```
PORT     STATE SERVICE
3000/tcp open  ppp
| mcp-discovery:
|   endpoints:
|     [1]
|       url: http://192.168.1.100:3000/ws
|       protocol: HTTP
|       transport: WEBSOCKET
|       methods:
|         initialize: Initialized successfully
|         tools/list: 1 tool available
|       server_info:
|         name: realtime-mcp
|       tools:
|_        stream_data: Stream real-time data
```

### Multiple Endpoints with Different Transports

```
PORT     STATE SERVICE
8080/tcp open  http-proxy
| mcp-discovery:
|   endpoints:
|     [1]
|       url: http://192.168.1.100:8080/mcp
|       protocol: HTTP
|       transport: HTTP
|       methods:
|         initialize: Initialized successfully
|         tools/list: 10 tools available
|         resources/list: 3 resources available
|       server_info:
|         name: filesystem-mcp
|         version: 2.1.0
|         protocolVersion: 2024-11-05
|       tools:
|         list_directory: List files in a directory
|         read_file: Read a file from the filesystem
|         write_file: Write data to a file
|         delete_file: Delete a file
|         create_directory: Create a new directory
|         move_file: Move or rename a file
|         copy_file: Copy a file
|         get_file_info: Get metadata about a file
|         search_files: Search for files matching a pattern
|         watch_directory: Monitor a directory for changes
|       resources:
|         file:///var/data: System data directory
|         file:///etc/config: Configuration files
|         file:///var/log: Log files
|     [2]
|       url: http://192.168.1.100:8080/sse
|       protocol: HTTP
|       transport: SSE
|       methods:
|         initialize: Initialized successfully
|         tools/list: 5 tools available
|       tools:
|         api_call: Make an API call
|         parse_json: Parse JSON data
|         format_data: Format data for output
|         validate_input: Validate user input
|_        transform_data: Transform data between formats
```

### No MCP Endpoints Found

If no MCP endpoints are found on a port, the script will not produce output for that port.

### Successful Brute Force Authentication

```
PORT     STATE SERVICE
8811/tcp open  unknown
| mcp-discovery:
|   endpoints:
|     [1]
|       url: http://192.168.1.100:8811/
|       protocol: HTTP
|       methods:
|         initialize: Authentication bypassed (token: dev)
|         tools/list: 5 tools available
|         resources/list: 2 resources available
|       server_info:
|         name: MCP Gateway (authenticated)
|         cracked_token: dev
|       tools:
|         shell_exec: Execute shell commands
|         file_read: Read files from filesystem
|         network_scan: Scan network for services
|         db_query: Execute database queries
|         api_proxy: Proxy API requests
|       resources:
|         file:///etc/config: Configuration files
|_        database://prod: Production database
```

## Script Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `mcp-discovery.paths` | Comma-separated list of ADDITIONAL paths to probe (default 27 paths always included) | None (uses 27 default paths) |
| `mcp-discovery.timeout` | Timeout for HTTP requests in milliseconds | `5000` |
| `mcp-discovery.useragent` | User-Agent header to use | `Nmap NSE` |
| `mcp-discovery.bruteforce` | Enable brute force authentication attempts | `false` |
| `mcp-discovery.passdb` | Path to password database for brute force | Nmap default |
| `mcp-discovery.userdb` | Path to username database for brute force | Nmap default |

## Comprehensive MCP Path Coverage

The script automatically probes **27 common MCP endpoint paths** based on research of popular MCP servers, gateways, and frameworks (2025):

**⚠️ IMPORTANT:** These paths are **ALWAYS tested by default** - you don't need to specify them! The `mcp-discovery.paths` argument is only for adding ADDITIONAL custom paths.

### Standard MCP Paths
- `/` - Root path (common for simple servers)
- `/mcp` - Standard MCP endpoint (Streamable HTTP)

### Legacy SSE Transport (pre-2025)
- `/sse` - Default SSE connection endpoint
- `/messages` - Default message POST endpoint for SSE
- `/mcp/stream` - Alternative SSE streaming path

### API Versioned Paths
- `/api/mcp` - API-prefixed MCP path
- `/v1/mcp` - Versioned MCP path
- `/api/v1/mcp` - API + version prefix
- `/v2/mcp` - Version 2 path

### Gateway and Proxy Paths
- `/mcpgw/mcp` - MCP Gateway proxy path (Microsoft/Docker)
- `/gateway/mcp` - Alternative gateway path
- `/proxy/mcp` - Proxy server path
- `/adapters` - MCP Gateway adapter endpoint
- `/tools` - Direct tools API

### Generic RPC Paths
- `/rpc` - Generic RPC endpoint
- `/jsonrpc` - JSON-RPC specific endpoint
- `/json-rpc` - Alternative JSON-RPC path

### Framework-Specific Paths
- `/message` - Message endpoint variant
- `/endpoint` - Generic endpoint path
- `/api` - Simple API path
- `/server` - Server endpoint path

### Transport-Specific Paths
- `/http` - HTTP transport explicit path
- `/stream` - Generic streaming path
- `/ws` - WebSocket path

## MCP Transport Support

The script supports all three official MCP transport methods as of the 2025 specification:

### HTTP (Streamable HTTP) Transport
**Status:** ✅ Fully Supported

The modern standard transport for MCP (2025+). Uses HTTP POST with JSON-RPC 2.0 payloads.

- **Detection:** Automatically used for standard paths like `/mcp`, `/api/mcp`, etc.
- **Protocol:** HTTP POST with `Content-Type: application/json`
- **Authentication:** Bearer token support
- **Implementation:** Full support including proper initialize → list methods flow

### SSE (Server-Sent Events) Transport
**Status:** ✅ Fully Supported

Legacy transport method used before the 2025 specification update.

- **Detection:** Automatically detected for paths containing `/sse`, `/messages`, `/stream`
- **Protocol:** GET request to establish SSE connection, POST to `/messages` for requests
- **Headers:** Uses `Accept: text/event-stream`
- **Implementation:** Properly handles SSE dual-endpoint model (connection + message endpoint)

### WebSocket Transport
**Status:** ✅ Fully Supported

Real-time bidirectional communication transport.

- **Detection:** Automatically detected for paths containing `/ws`, `/websocket`
- **Protocol:** WebSocket upgrade handshake followed by framed JSON-RPC messages
- **Headers:** Standard WebSocket upgrade headers (`Upgrade: websocket`, `Connection: Upgrade`)
- **Authentication:** Bearer token support in handshake
- **Implementation:** Full WebSocket handshake and frame parsing

### Transport Auto-Detection

The script intelligently detects the correct transport based on the path:

```lua
/sse, /messages, /stream → SSE Transport
/ws, /websocket → WebSocket Transport
All other paths → HTTP (Streamable HTTP) Transport
```

This means you don't need to specify the transport - the script will automatically use the correct protocol for each path!

## Popular MCP Servers Detected

This script can detect MCP endpoints from popular servers and frameworks:

### Official Anthropic Servers
- **@modelcontextprotocol/server-filesystem** - Local file operations
- **@modelcontextprotocol/server-github** - GitHub repository management
- **@modelcontextprotocol/server-puppeteer** - Browser automation
- **@modelcontextprotocol/server-slack** - Slack workspace integration
- **@modelcontextprotocol/server-postgres** - PostgreSQL database access
- **@modelcontextprotocol/server-brave-search** - Brave Search API

### Enterprise Gateways
- **Microsoft MCP Gateway** - Kubernetes-based reverse proxy
- **Docker MCP Gateway** - Container-based MCP routing
- **IBM ContextForge** - Enterprise MCP gateway
- **Traefik Hub MCP Gateway** - API gateway integration
- **LiteLLM MCP** - Multi-model MCP integration

### Community Servers
- **Memory servers** - Context persistence
- **SQLite servers** - Local database operations
- **Git servers** - Version control integration
- **Google Drive servers** - Cloud storage access

## Integration with Nmap

### Save Results to File

```bash
# XML format
nmap -p 80,443,3000-3100 -sV --script mcp-discovery -oX mcp-scan.xml <target>

# Normal format
nmap -p 80,443,3000-3100 -sV --script mcp-discovery -oN mcp-scan.txt <target>

# All formats
nmap -p 80,443,3000-3100 -sV --script mcp-discovery -oA mcp-scan <target>
```

### Combine with Other Scripts

```bash
nmap -p 80,443 -sV --script http-enum,mcp-discovery <target>
```

## Performance Tips

1. **Target Specific Ports**: Instead of scanning all ports, target common web service ports to speed up scans:
   ```bash
   nmap -p 80,443,3000,3001,8080,8443 -sV --script mcp-discovery <target>
   ```

2. **Use Lighter Service Detection**: For faster scans, use lighter service detection:
   ```bash
   nmap -p- -sV --version-intensity 0 --script mcp-discovery <target>
   ```

3. **Parallel Scanning**: Scan multiple hosts in parallel:
   ```bash
   nmap -p 80,443,3000 -sV --script mcp-discovery --min-hostgroup 10 192.168.1.0/24
   ```

## Security Considerations

### Read-Only Operations
- This script performs **safe, read-only operations** by default
- It sends standard JSON-RPC 2.0 requests that do not modify server state
- The script only calls MCP "list" methods and "initialize" which are non-destructive

### Brute Force Feature
- **Brute force is disabled by default** and must be explicitly enabled
- When enabled, the script attempts common/default tokens before trying custom wordlists
- Brute force attempts include small delays (50ms) to avoid overwhelming servers
- Successfully cracked tokens are displayed in the output
- **IMPORTANT**: Only use brute force on systems you have explicit authorization to test
- Unauthorized brute force attempts may be illegal and could trigger security alerts

### Responsible Use
- **Only scan networks and systems you have permission to test**
- Respect rate limits and avoid aggressive scanning
- Be aware that some MCP Gateways may log failed authentication attempts
- Consider legal and ethical implications before enabling brute force

## Troubleshooting

### Script Not Found

If you get "NSE: failed to initialize the script engine", ensure:
1. The script is in the correct directory
2. You've run `nmap --script-updatedb`
3. Or use the full path: `nmap --script ./mcp-discovery.nse`

### No Output

If the script produces no output:
1. **Make sure you're using `-sV`**: The script requires service detection to work
2. Verify the target host is running an HTTP service: `nmap -sV -p <port> <target>`
3. Enable debug mode: `nmap -sV -d --script mcp-discovery <target>`
4. Check if the MCP server is on a non-standard path (use custom paths argument)
5. Ensure the MCP server is actually running and accessible

**Common mistake:** Running without `-sV` flag. This script uses service detection to identify HTTP services on any port, so `-sV` is required!

### JSON Parse Errors

If you see JSON parsing errors in debug mode:
- The service may not be an MCP endpoint
- The server may be returning HTML or other non-JSON content
- This is normal behavior and the script will move on to the next path

## Testing the Script

### Test Against a Local MCP Server

If you have an MCP server running locally on port 3000:

```bash
nmap -p 3000 -sV --script mcp-discovery localhost
```

### Test Syntax

Verify the script syntax:

```bash
nmap --script-help mcp-discovery
```

### Dry Run

Test without actually scanning (validate script loads):

```bash
nmap -sV --script mcp-discovery --script-trace localhost -p 80 -Pn
```

## Example Workflow

Complete MCP endpoint discovery workflow:

```bash
# 1. Quick scan on common ports
nmap -p 80,443,3000-3100 -sV --script mcp-discovery 192.168.1.0/24 -oN quick-scan.txt

# 2. Deep scan on hosts that responded
nmap -p- -sV --script mcp-discovery 192.168.1.50 -oN deep-scan.txt

# 3. Detailed investigation with verbose output
nmap -p 3000 -sV --script mcp-discovery -v 192.168.1.50
```

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

Copyright (C) 2025 IntegSec

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

**Special Note for Nmap Distribution:**
This script is provided under GPL v3 or later. In accordance with Nmap's license requirements, this script may also be distributed under the Nmap Public Source License (NPSL) or the Nmap license when distributed as part of the official Nmap distribution. When distributed independently of Nmap, the GPL v3 or later applies.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

For more information about Nmap's license, see: https://nmap.org/book/man-legal.html

## References

- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [Nmap Scripting Engine Documentation](https://nmap.org/book/nse.html)
- [JSON-RPC 2.0 Specification](https://www.jsonrpc.org/specification)

## Author

**IntegSec** - https://integsec.com

Created for MCP endpoint discovery and network reconnaissance.
