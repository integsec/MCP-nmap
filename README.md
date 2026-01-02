# MCP Discovery NSE Script for Nmap

An Nmap Scripting Engine (NSE) script that discovers Model Context Protocol (MCP) endpoints by probing HTTP and WebSocket services with JSON-RPC 2.0 requests.

**Developed by [IntegSec](https://integsec.com)**

## What is MCP?

The Model Context Protocol (MCP) is an open protocol that enables AI assistants to securely access tools, resources, and prompts from external servers. This script helps identify MCP-enabled services on a network.

## Features

- Discovers MCP endpoints on HTTP/HTTPS services
- Tests common MCP paths automatically
- Probes for standard MCP methods:
  - `tools/list` - Enumerates available tools
  - `resources/list` - Lists available resources
  - `prompts/list` - Shows available prompts
  - `initialize` - MCP initialization handshake
- Extracts server information (name, version, protocol version)
- Safe and non-intrusive scanning
- Customizable paths and timeout settings

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

### Basic Scan

Scan a single host on common web ports:

```bash
nmap -p 80,443,3000-3100 --script mcp-discovery <target>
```

### Scan All Ports

Scan all ports for MCP endpoints:

```bash
nmap -p- --script mcp-discovery <target>
```

### Scan Multiple Hosts

Scan a network range:

```bash
nmap -p 80,443,3000-3100 --script mcp-discovery 192.168.1.0/24
```

### Scan from File

Scan hosts listed in a file:

```bash
nmap -p 80,443,3000-3100 --script mcp-discovery -iL targets.txt
```

### Custom Paths

Specify custom paths to probe:

```bash
nmap -p 80,443 --script mcp-discovery --script-args mcp-discovery.paths=/api/v1/mcp,/custom/endpoint <target>
```

### Adjust Timeout

Set a custom timeout (default is 5000ms):

```bash
nmap -p 80,443 --script mcp-discovery --script-args mcp-discovery.timeout=10000 <target>
```

### Verbose Output

Get more detailed information:

```bash
nmap -p 80,443 --script mcp-discovery -v <target>
```

### Debug Mode

Enable debug output for troubleshooting:

```bash
nmap -p 80,443 --script mcp-discovery -d <target>
```

## Output Examples

### Successful MCP Discovery

```
PORT     STATE SERVICE
3000/tcp open  ppp
| mcp-discovery:
|   endpoints:
|     url: http://192.168.1.100:3000/mcp
|     protocol: HTTP
|     methods:
|       tools/list: 3 tools available
|       resources/list: 5 resources available
|       prompts/list: 2 prompts available
|       initialize: Initialized successfully
|     server_info:
|       name: example-mcp-server
|       version: 1.0.0
|_      protocolVersion: 2024-11-05
```

### Multiple Endpoints Found

```
PORT     STATE SERVICE
8080/tcp open  http-proxy
| mcp-discovery:
|   endpoints:
|     [1]
|       url: http://192.168.1.100:8080/mcp
|       protocol: HTTP
|       methods:
|         tools/list: 10 tools available
|         resources/list: 3 resources available
|       server_info:
|         name: filesystem-mcp
|         version: 2.1.0
|         protocolVersion: 2024-11-05
|     [2]
|       url: http://192.168.1.100:8080/api/mcp
|       protocol: HTTP
|       methods:
|         tools/list: 5 tools available
|_        initialize: Initialized successfully
```

### No MCP Endpoints Found

If no MCP endpoints are found on a port, the script will not produce output for that port.

## Script Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `mcp-discovery.paths` | Comma-separated list of paths to probe | `/,/mcp,/mcp/stream,/api/mcp,/v1/mcp,/rpc,/jsonrpc,/sse,/messages` |
| `mcp-discovery.timeout` | Timeout for HTTP requests in milliseconds | `5000` |
| `mcp-discovery.useragent` | User-Agent header to use | `Nmap NSE` |

## Common MCP Paths

The script automatically probes these common paths:

- `/` - Root path
- `/mcp` - Standard MCP path
- `/mcp/stream` - MCP streaming endpoint
- `/api/mcp` - API-prefixed MCP path
- `/v1/mcp` - Versioned MCP path
- `/rpc` - Generic RPC path
- `/jsonrpc` - JSON-RPC path
- `/sse` - Server-Sent Events path
- `/messages` - Messages endpoint

## Integration with Nmap

### Combine with Service Detection

```bash
nmap -sV -p- --script mcp-discovery <target>
```

### Save Results to File

```bash
# XML format
nmap -p 80,443,3000-3100 --script mcp-discovery -oX mcp-scan.xml <target>

# Normal format
nmap -p 80,443,3000-3100 --script mcp-discovery -oN mcp-scan.txt <target>

# All formats
nmap -p 80,443,3000-3100 --script mcp-discovery -oA mcp-scan <target>
```

### Combine with Other Scripts

```bash
nmap -p 80,443 --script http-enum,mcp-discovery <target>
```

## Performance Tips

1. **Target Specific Ports**: Instead of scanning all ports, target common web service ports to speed up scans:
   ```bash
   nmap -p 80,443,3000,3001,8080,8443 --script mcp-discovery <target>
   ```

2. **Reduce Paths**: If you know the specific MCP path, specify it to reduce scan time:
   ```bash
   nmap --script mcp-discovery --script-args mcp-discovery.paths=/mcp <target>
   ```

3. **Parallel Scanning**: Scan multiple hosts in parallel:
   ```bash
   nmap -p 80,443,3000 --script mcp-discovery --min-hostgroup 10 192.168.1.0/24
   ```

## Security Considerations

- This script performs **safe, read-only operations**
- It sends standard JSON-RPC 2.0 requests that do not modify server state
- The script only calls MCP "list" methods and "initialize" which are non-destructive
- Use responsibly and only scan networks you have permission to test

## Troubleshooting

### Script Not Found

If you get "NSE: failed to initialize the script engine", ensure:
1. The script is in the correct directory
2. You've run `nmap --script-updatedb`
3. Or use the full path: `nmap --script ./mcp-discovery.nse`

### No Output

If the script produces no output:
1. Verify the target host is running an HTTP service: `nmap -sV -p <port> <target>`
2. Enable debug mode: `nmap -d --script mcp-discovery <target>`
3. Check if the MCP server is on a non-standard path (use custom paths argument)
4. Ensure the MCP server is actually running and accessible

### JSON Parse Errors

If you see JSON parsing errors in debug mode:
- The service may not be an MCP endpoint
- The server may be returning HTML or other non-JSON content
- This is normal behavior and the script will move on to the next path

## Testing the Script

### Test Against a Local MCP Server

If you have an MCP server running locally on port 3000:

```bash
nmap -p 3000 --script mcp-discovery localhost
```

### Test Syntax

Verify the script syntax:

```bash
nmap --script-help mcp-discovery
```

### Dry Run

Test without actually scanning (validate script loads):

```bash
nmap --script mcp-discovery --script-trace localhost -p 80 -Pn
```

## Example Workflow

Complete MCP endpoint discovery workflow:

```bash
# 1. Quick scan on common ports
nmap -p 80,443,3000-3100 --script mcp-discovery 192.168.1.0/24 -oN quick-scan.txt

# 2. Deep scan on hosts that responded
nmap -p- --script mcp-discovery 192.168.1.50 -oN deep-scan.txt

# 3. Detailed investigation with verbose output
nmap -p 3000 --script mcp-discovery -sV -v 192.168.1.50
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
