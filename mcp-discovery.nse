-- MCP Discovery - Nmap NSE Script for Model Context Protocol Endpoint Detection
-- Copyright (C) 2025 IntegSec
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version, with the clarification and special
-- exception below.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- CLARIFICATION AND SPECIAL EXCEPTION:
-- This script is provided under GPL v3 or later for distribution with Nmap.
-- In accordance with Nmap's license requirements, this script may also be
-- distributed under the Nmap Public Source License (NPSL) or the Nmap
-- license when distributed as part of the official Nmap distribution.
-- When distributed independently of Nmap, the GPL v3 or later applies.
--
-- You should have received a copy of the GNU General Public License
-- along with this program. If not, see <https://www.gnu.org/licenses/>.
--
-- For the Nmap license, see: https://nmap.org/book/man-legal.html

local http = require "http"
local json = require "json"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local brute = require "brute"
local creds = require "creds"
local unpwdb = require "unpwdb"
local comm = require "comm"

description = [[
Discovers Model Context Protocol (MCP) endpoints by probing HTTP, SSE, and WebSocket services
with JSON-RPC 2.0 requests. MCP is a protocol that allows AI assistants to access tools,
resources, and prompts from external servers.

The script supports all three MCP transport methods:
- HTTP (Streamable HTTP) - The 2025 standard transport
- SSE (Server-Sent Events) - Legacy transport (pre-2025)
- WebSocket - For real-time bidirectional communication

The script tests common MCP paths and checks for valid JSON-RPC 2.0 responses to the
following MCP methods:
- initialize (MCP initialization handshake - MUST be first)
- tools/list (lists available tools)
- resources/list (lists available resources)
- prompts/list (lists available prompts)

When authentication is required, the script can optionally attempt brute force with
common credentials (opt-in via --script-args mcp-discovery.bruteforce=true).

Copyright (C) 2025 IntegSec - https://integsec.com
]]

---
-- @usage
-- nmap -p 80,443,3000-3100 --script mcp-discovery <target>
-- nmap -p- --script mcp-discovery --script-args mcp-discovery.paths=/custom/mcp <target>
--
-- @output
-- PORT     STATE SERVICE
-- 3000/tcp open  ppp
-- | mcp-discovery:
-- |   endpoints:
-- |     [1]
-- |       url: http://192.168.1.100:3000/mcp
-- |       protocol: HTTP
-- |       transport: HTTP
-- |       methods:
-- |         initialize: Initialized successfully
-- |         tools/list: 3 tools available
-- |         resources/list: 5 resources available
-- |         prompts/list: 2 prompts available
-- |       server_info:
-- |         name: example-mcp-server
-- |         version: 1.0.0
-- |         protocolVersion: 2024-11-05
-- |       tools:
-- |         read_file: Read contents of a file
-- |         write_file: Write content to a file
-- |         execute_command: Execute a shell command
-- |       resources:
-- |         file:///home/user/docs: Project documentation (text/markdown)
-- |         file:///home/user/data: Data directory (application/x-directory)
-- |         config://app: Application configuration
-- |         database://main: Main database connection
-- |         cache://redis: Redis cache instance
-- |       prompts:
-- |         code_review: Review code for best practices
-- |         bug_analysis: Analyze bugs and suggest fixes
-- |     [2]
-- |       url: http://192.168.1.100:3000/sse
-- |       protocol: HTTP
-- |       transport: SSE
-- |       methods:
-- |         initialize: Initialized successfully
-- |_        tools/list: 1 tool available
--
-- @args mcp-discovery.paths Comma-separated list of ADDITIONAL paths to probe (default paths are always included)
-- @args mcp-discovery.timeout Timeout for HTTP requests in milliseconds (default: 5000)
-- @args mcp-discovery.useragent User-Agent header to use (default: Nmap NSE)
-- @args mcp-discovery.bruteforce Enable brute force authentication attempts when encountering protected endpoints (default: false)
-- @args mcp-discovery.passdb Path to password database for brute force (uses Nmap default if not specified)
-- @args mcp-discovery.userdb Path to username database for brute force (uses Nmap default if not specified)

author = "IntegSec <https://integsec.com>"
license = "GPLv3+ (GPL version 3 or later) - Compatible with Nmap license for distribution"
categories = {"discovery", "safe", "default"}  -- Safe by default; brute force is opt-in

-- Default paths to probe for MCP endpoints
-- Based on common MCP server implementations, gateways, and frameworks (2025)
local DEFAULT_PATHS = {
  -- Standard MCP paths
  "/",                    -- Root path (common for simple servers)
  "/mcp",                 -- Standard MCP endpoint (Streamable HTTP)

  -- Legacy SSE transport paths (pre-2025)
  "/sse",                 -- Default SSE connection endpoint
  "/messages",            -- Default message POST endpoint for SSE
  "/mcp/stream",          -- Alternative SSE streaming path

  -- API versioned paths
  "/api/mcp",             -- API-prefixed MCP path
  "/v1/mcp",              -- Versioned MCP path
  "/api/v1/mcp",          -- API + version prefix
  "/v2/mcp",              -- Version 2 path

  -- Gateway and proxy paths
  "/mcpgw/mcp",           -- MCP Gateway proxy path
  "/gateway/mcp",         -- Alternative gateway path
  "/proxy/mcp",           -- Proxy server path
  "/adapters",            -- MCP Gateway adapter endpoint
  "/tools",               -- Direct tools API (some implementations)

  -- Generic RPC paths
  "/rpc",                 -- Generic RPC endpoint
  "/jsonrpc",             -- JSON-RPC specific endpoint
  "/json-rpc",            -- Alternative JSON-RPC path

  -- Framework-specific paths
  "/message",             -- Message endpoint variant
  "/endpoint",            -- Generic endpoint path
  "/api",                 -- Simple API path
  "/server",              -- Server endpoint path

  -- Transport-specific paths
  "/http",                -- HTTP transport explicit path
  "/stream",              -- Generic streaming path
  "/ws",                  -- WebSocket path (future support)
}

-- Rule to determine if script should run
portrule = function(host, port)
  -- Run on any port where service detection identified HTTP/HTTPS or WebSocket
  -- This works regardless of port number and relies on Nmap's service detection
  -- Note: WebSocket servers typically also respond to HTTP, but we include it for completeness
  return shortport.http(host, port) or
         (port.service and port.service:match("websocket"))
end

-- Create a JSON-RPC 2.0 request
local function create_jsonrpc_request(method, params)
  return json.generate({
    jsonrpc = "2.0",
    id = 1,
    method = method,
    params = params or {}
  })
end

-- Detect transport type based on path
local function detect_transport_type(path)
  -- SSE transport paths (legacy pre-2025)
  if path:match("/sse") or path:match("/stream") or path:match("/messages") then
    return "sse"
  -- WebSocket paths
  elseif path:match("/ws") or path:match("/websocket") then
    return "websocket"
  -- Default to HTTP (Streamable HTTP is the 2025 standard)
  else
    return "http"
  end
end

-- Send SSE request (legacy transport)
-- SSE uses GET for connection + POST to /messages for requests
local function send_sse_request(host, port, path, method, params, bearer_token)
  stdnse.debug1("Using SSE transport for %s", path)

  -- SSE requires two endpoints:
  -- 1. GET /sse to establish connection
  -- 2. POST /messages to send requests

  local message_path = path
  if path:match("/sse$") then
    -- If path is /sse, POST to /messages
    message_path = path:gsub("/sse$", "/messages")
  elseif not path:match("/messages$") then
    -- If path doesn't end in /messages, try appending it
    if path:match("/$") then
      message_path = path .. "messages"
    else
      message_path = path .. "/messages"
    end
  end

  local payload = create_jsonrpc_request(method, params)

  local options = {
    header = {
      ["Content-Type"] = "application/json",
      ["Accept"] = "text/event-stream"  -- SSE content type
    },
    content = payload
  }

  if bearer_token then
    options.header["Authorization"] = "Bearer " .. bearer_token
  end

  stdnse.debug2("SSE POST to %s with payload: %s", message_path, payload)

  -- Send POST to message endpoint
  local response = http.post(host, port, message_path, options)

  if response and response.body then
    stdnse.debug2("SSE response body: %s", response.body:sub(1, 500))
  end

  return response
end

-- Send HTTP POST request with JSON-RPC payload (Streamable HTTP transport)
local function send_http_request(host, port, path, method, params, bearer_token)
  local payload = create_jsonrpc_request(method, params)

  local options = {
    header = {
      ["Content-Type"] = "application/json",
      ["Accept"] = "application/json"
    },
    content = payload
  }

  -- Add Bearer token if provided
  if bearer_token then
    options.header["Authorization"] = "Bearer " .. bearer_token
  end

  stdnse.debug1("Probing %s:%d%s with method %s (HTTP transport)", host.ip, port.number, path, method)
  stdnse.debug2("Request payload: %s", payload)

  local response = http.post(host, port, path, options)

  if response and response.body then
    stdnse.debug2("Response body: %s", response.body:sub(1, 500))
  end

  return response
end

-- Send WebSocket request with JSON-RPC payload
local function send_websocket_request(host, port, path, method, params, bearer_token)
  stdnse.debug1("Using WebSocket transport for %s", path)

  -- WebSocket upgrade and communication
  local payload = create_jsonrpc_request(method, params)

  -- Build WebSocket handshake
  local handshake = string.format(
    "GET %s HTTP/1.1\r\n" ..
    "Host: %s:%d\r\n" ..
    "Upgrade: websocket\r\n" ..
    "Connection: Upgrade\r\n" ..
    "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n" ..
    "Sec-WebSocket-Version: 13\r\n",
    path, host.ip, port.number
  )

  if bearer_token then
    handshake = handshake .. string.format("Authorization: Bearer %s\r\n", bearer_token)
  end

  handshake = handshake .. "\r\n"

  -- Attempt WebSocket connection
  local socket = comm.tryssl(host, port, "", {timeout=5000})

  if not socket then
    stdnse.debug2("Failed to create socket for WebSocket connection")
    return nil
  end

  -- Send handshake
  local status, err = socket:send(handshake)
  if not status then
    stdnse.debug2("Failed to send WebSocket handshake: %s", err or "unknown")
    socket:close()
    return nil
  end

  -- Receive handshake response
  local status, response_data = socket:receive()
  if not status then
    stdnse.debug2("Failed to receive WebSocket handshake response: %s", response_data or "unknown")
    socket:close()
    return nil
  end

  -- Check if upgrade was successful
  if not response_data:match("101 Switching Protocols") then
    stdnse.debug2("WebSocket upgrade failed: %s", response_data:sub(1, 200))
    socket:close()
    return nil
  end

  stdnse.debug2("WebSocket connection established")

  -- Send JSON-RPC message as WebSocket frame
  -- Simple text frame (opcode 0x1)
  local frame = string.char(0x81) .. string.char(#payload) .. payload

  status, err = socket:send(frame)
  if not status then
    stdnse.debug2("Failed to send WebSocket frame: %s", err or "unknown")
    socket:close()
    return nil
  end

  -- Receive WebSocket frame response
  status, response_data = socket:receive()
  socket:close()

  if not status then
    stdnse.debug2("Failed to receive WebSocket response: %s", response_data or "unknown")
    return nil
  end

  -- Parse WebSocket frame (skip first 2 bytes for simple frames)
  local json_response = response_data:sub(3)

  -- Return in same format as HTTP response
  return {
    status = 200,
    body = json_response,
    header = {}
  }
end

-- Send MCP request using appropriate transport
local function send_mcp_request(host, port, path, method, params, bearer_token)
  local transport = detect_transport_type(path)

  if transport == "sse" then
    return send_sse_request(host, port, path, method, params, bearer_token)
  elseif transport == "websocket" then
    return send_websocket_request(host, port, path, method, params, bearer_token)
  else
    return send_http_request(host, port, path, method, params, bearer_token)
  end
end

-- Parse and validate JSON-RPC response
local function parse_jsonrpc_response(response)
  if not response or not response.body then
    return nil, "No response body"
  end

  local status, parsed = json.parse(response.body)
  if not status then
    return nil, "Invalid JSON"
  end

  -- Check for JSON-RPC 2.0 response structure
  if parsed.jsonrpc ~= "2.0" then
    return nil, "Not a JSON-RPC 2.0 response"
  end

  if parsed.error then
    -- Valid JSON-RPC error is still a valid MCP response
    return {
      is_error = true,
      error = parsed.error,
      id = parsed.id
    }
  end

  if parsed.result ~= nil then
    return {
      is_error = false,
      result = parsed.result,
      id = parsed.id
    }
  end

  return nil, "Invalid JSON-RPC response structure"
end

-- Attempt to brute force Bearer token authentication
local function brute_force_bearer_token(host, port, path)
  stdnse.debug1("Attempting brute force on %s", path)

  -- Common MCP Gateway tokens and API keys to try
  local common_tokens = {
    -- Development/default tokens
    "dev",
    "development",
    "test",
    "testing",
    "admin",
    "default",
    "mcp",
    "mcpgateway",
    "gateway",
    "changeme",
    "password",
    "secret",
    "token",
    "apikey",
    "key",
    -- Common weak tokens
    "12345",
    "123456",
    "password123",
    "admin123",
    -- Empty/placeholder tokens
    "",
    "null",
    "none",
  }

  -- Try common tokens first
  for _, token in ipairs(common_tokens) do
    stdnse.debug2("Trying token: %s", token == "" and "(empty)" or token)

    local init_response = send_mcp_request(host, port, path, "initialize", {
      protocolVersion = "2024-11-05",
      capabilities = {},
      clientInfo = {
        name = "nmap-mcp-discovery",
        version = "1.0.0"
      }
    }, token)

    if init_response and init_response.status == 200 then
      local parsed = parse_jsonrpc_response(init_response)
      if parsed and not parsed.is_error then
        stdnse.debug1("Successful authentication with token: %s", token == "" and "(empty)" or token)
        return true, token
      end
    end

    stdnse.sleep(0.05)  -- Small delay to avoid overwhelming the server
  end

  -- If user provided databases, try those
  local userdb = stdnse.get_script_args("mcp-discovery.userdb")
  local passdb = stdnse.get_script_args("mcp-discovery.passdb")

  if passdb then
    stdnse.debug1("Trying tokens from password database: %s", passdb)
    local status, passwords = unpwdb.passwords(passdb)
    if status then
      for password in passwords do
        stdnse.debug2("Trying token from db: %s", password)

        local init_response = send_mcp_request(host, port, path, "initialize", {
          protocolVersion = "2024-11-05",
          capabilities = {},
          clientInfo = {
            name = "nmap-mcp-discovery",
            version = "1.0.0"
          }
        }, password)

        if init_response and init_response.status == 200 then
          local parsed = parse_jsonrpc_response(init_response)
          if parsed and not parsed.is_error then
            stdnse.debug1("Successful authentication with token from db: %s", password)
            return true, password
          end
        end

        stdnse.sleep(0.05)
      end
    end
  end

  return false, nil
end

-- Probe a specific path for MCP endpoint
local function probe_path(host, port, path)
  local results = {}

  local mcp_found = false
  local method_results = {}
  local server_info = {}
  local tools_list = {}
  local resources_list = {}
  local prompts_list = {}
  local initialized = false
  local bearer_token = nil  -- Store token if authentication succeeds
  local detected_transport = detect_transport_type(path)  -- Detect transport type

  -- Step 1: Initialize the connection (MUST be first in MCP protocol)
  stdnse.debug1("Attempting to initialize MCP connection at %s", path)
  local init_response = send_mcp_request(host, port, path, "initialize", {
    protocolVersion = "2024-11-05",
    capabilities = {},
    clientInfo = {
      name = "nmap-mcp-discovery",
      version = "1.0.0"
    }
  })

  if init_response and init_response.status == 200 then
    local parsed, err = parse_jsonrpc_response(init_response)
    if parsed and not parsed.is_error and parsed.result then
      mcp_found = true
      initialized = true
      method_results["initialize"] = "Initialized successfully"

      -- Extract server info
      if parsed.result.serverInfo then
        server_info = parsed.result.serverInfo
      end
      if parsed.result.protocolVersion then
        server_info.protocolVersion = parsed.result.protocolVersion
      end
      if parsed.result.capabilities then
        server_info.capabilities = parsed.result.capabilities
      end

      stdnse.debug1("MCP initialized successfully, protocol version: %s",
                    parsed.result.protocolVersion or "unknown")
    elseif parsed and parsed.is_error then
      mcp_found = true
      if parsed.error and parsed.error.message then
        method_results["initialize"] = string.format("Error: %s", parsed.error.message)
      end
      stdnse.debug2("Initialize failed: %s", json.generate(parsed.error))
    end
  elseif init_response and init_response.status == 401 then
    -- HTTP 401 Unauthorized - Check if it's an MCP Gateway requiring auth
    mcp_found = true
    local auth_header = init_response.header["www-authenticate"] or init_response.header["WWW-Authenticate"]
    if auth_header and string.match(auth_header:lower(), "bearer") then
      server_info.name = "MCP Gateway (authenticated)"
      server_info.auth_required = true
      stdnse.debug1("MCP endpoint found but requires Bearer token authentication")

      -- Attempt brute force if enabled
      local bruteforce_enabled = stdnse.get_script_args("mcp-discovery.bruteforce")
      if bruteforce_enabled == "true" or bruteforce_enabled == "1" then
        local success, token = brute_force_bearer_token(host, port, path)
        if success then
          method_results["initialize"] = string.format("Authentication bypassed (token: %s)", token == "" and "(empty)" or token)
          server_info.cracked_token = token
          server_info.auth_required = false  -- Auth was cracked, can proceed
          initialized = true  -- Mark as initialized since we got in
          bearer_token = token  -- Store token for subsequent requests
          stdnse.debug1("Brute force successful!")
        else
          method_results["initialize"] = "Requires authentication (Bearer token) - brute force failed"
          stdnse.debug1("Brute force failed")
        end
      else
        method_results["initialize"] = "Requires authentication (Bearer token)"
      end
    else
      method_results["initialize"] = "Requires authentication"
    end
  end

  -- Step 2: Only proceed with other methods if initialization succeeded
  if not initialized then
    stdnse.debug1("MCP initialization failed, skipping other methods")
    if mcp_found then
      -- Return what we have even if init failed
      return {
        path = path,
        methods = method_results,
        server_info = server_info,
        tools = tools_list,
        resources = resources_list,
        prompts = prompts_list
      }
    end
    return nil
  end

  -- Step 3: Now probe the list methods (order matters less after init)
  local list_methods = {
    {name = "tools/list", params = {}},
    {name = "resources/list", params = {}},
    {name = "prompts/list", params = {}}
  }

  for _, method_info in ipairs(list_methods) do
    stdnse.sleep(0.1)  -- Small delay between requests
    local response = send_mcp_request(host, port, path, method_info.name, method_info.params, bearer_token)

    if response and response.status == 200 then
      local parsed, err = parse_jsonrpc_response(response)

      if parsed then
        mcp_found = true

        if not parsed.is_error then
          -- Store successful method result
          if method_info.name == "tools/list" then
            if parsed.result and parsed.result.tools then
              local count = #parsed.result.tools
              if count > 0 then
                method_results[method_info.name] = string.format("%d tool%s available", count, count ~= 1 and "s" or "")
                -- Extract tool details
                for _, tool in ipairs(parsed.result.tools) do
                  local tool_info = tool.name or "unknown"
                  if tool.description then
                    tool_info = tool_info .. ": " .. tool.description
                  end
                  table.insert(tools_list, tool_info)
                end
              else
                method_results[method_info.name] = "No tools available"
              end
            else
              stdnse.debug2("tools/list returned unexpected format")
            end
          elseif method_info.name == "resources/list" then
            if parsed.result and parsed.result.resources then
              local count = #parsed.result.resources
              if count > 0 then
                method_results[method_info.name] = string.format("%d resource%s available", count, count ~= 1 and "s" or "")
                -- Extract resource details
                for _, resource in ipairs(parsed.result.resources) do
                  local res_info = resource.uri or resource.name or "unknown"
                  if resource.description then
                    res_info = res_info .. ": " .. resource.description
                  elseif resource.mimeType then
                    res_info = res_info .. " (" .. resource.mimeType .. ")"
                  end
                  table.insert(resources_list, res_info)
                end
              else
                method_results[method_info.name] = "No resources available"
              end
            else
              stdnse.debug2("resources/list returned unexpected format")
            end
          elseif method_info.name == "prompts/list" then
            if parsed.result and parsed.result.prompts then
              local count = #parsed.result.prompts
              if count > 0 then
                method_results[method_info.name] = string.format("%d prompt%s available", count, count ~= 1 and "s" or "")
                -- Extract prompt details
                for _, prompt in ipairs(parsed.result.prompts) do
                  local prompt_info = prompt.name or "unknown"
                  if prompt.description then
                    prompt_info = prompt_info .. ": " .. prompt.description
                  end
                  table.insert(prompts_list, prompt_info)
                end
              else
                method_results[method_info.name] = "No prompts available"
              end
            else
              stdnse.debug2("prompts/list returned unexpected format")
            end
          end
        else
          -- Error response - show the error
          if parsed.error and parsed.error.message then
            method_results[method_info.name] = string.format("Error: %s", parsed.error.message)
            stdnse.debug2("Method %s returned error: %s", method_info.name, json.generate(parsed.error))
          else
            method_results[method_info.name] = "Error (see debug output)"
            stdnse.debug2("Method %s returned error: %s", method_info.name, json.generate(parsed.error))
          end
        end
      end
    elseif response then
      -- Non-200 response
      stdnse.debug2("Method %s returned HTTP %d", method_info.name, response.status)
    end
  end

  -- Return results
  if mcp_found then
    return {
      path = path,
      transport = detected_transport,  -- Include detected transport type
      methods = method_results,
      server_info = server_info,
      tools = tools_list,
      resources = resources_list,
      prompts = prompts_list
    }
  end

  return nil
end

-- Check if a path is a child of any authenticated parent path
local function is_child_of_authenticated_path(path, auth_paths)
  for _, auth_path in ipairs(auth_paths) do
    -- Check if current path starts with an authenticated parent path
    -- and is not the same path
    if path ~= auth_path and path:sub(1, #auth_path) == auth_path then
      return true, auth_path
    end
  end
  return false, nil
end

-- Main action function
action = function(host, port)
  local output = stdnse.output_table()
  local endpoints_found = {}
  local authenticated_paths = {}  -- Track paths that require authentication

  -- Start with default paths and add custom paths if provided
  local paths = {}

  -- Always use the comprehensive default paths
  for _, path in ipairs(DEFAULT_PATHS) do
    table.insert(paths, path)
  end

  -- Add custom paths from script args (if any)
  local paths_arg = stdnse.get_script_args("mcp-discovery.paths")
  if paths_arg then
    stdnse.debug1("Adding custom paths: %s", paths_arg)
    for path in string.gmatch(paths_arg, "[^,]+") do
      -- Trim whitespace
      path = path:match("^%s*(.-)%s*$")
      -- Only add if not already in list
      local already_exists = false
      for _, existing_path in ipairs(paths) do
        if existing_path == path then
          already_exists = true
          break
        end
      end
      if not already_exists then
        table.insert(paths, path)
        stdnse.debug1("Added custom path: %s", path)
      end
    end
  end

  -- Determine protocol (http or https)
  local protocol = "http"
  if port.service == "https" or port.number == 443 or port.number == 8443 then
    protocol = "https"
  end

  -- Probe each path
  for _, path in ipairs(paths) do
    -- Skip this path if it's a child of an authenticated path
    local is_child, parent_path = is_child_of_authenticated_path(path, authenticated_paths)
    if is_child then
      stdnse.debug1("Skipping %s (parent path %s requires authentication)", path, parent_path)
      goto continue
    end

    local result = probe_path(host, port, path)

    -- Track if this path requires authentication
    if result and result.server_info and result.server_info.auth_required then
      table.insert(authenticated_paths, path)
      stdnse.debug1("Added %s to authenticated paths list", path)
    end

    if result then
      local endpoint_url = string.format("%s://%s:%d%s", protocol, host.ip, port.number, path)
      local endpoint_output = stdnse.output_table()

      endpoint_output.url = endpoint_url
      endpoint_output.protocol = string.upper(protocol)

      -- Add transport type
      if result.transport then
        endpoint_output.transport = string.upper(result.transport)
      end

      -- Add methods information in consistent order
      if next(result.methods) then
        endpoint_output.methods = {}
        -- Show in logical order: initialize first, then list methods
        local method_order = {"initialize", "tools/list", "resources/list", "prompts/list"}
        for _, method in ipairs(method_order) do
          if result.methods[method] then
            table.insert(endpoint_output.methods, string.format("%s: %s", method, result.methods[method]))
          end
        end
      end

      -- Add server information
      if next(result.server_info) then
        endpoint_output.server_info = {}
        if result.server_info.name then
          table.insert(endpoint_output.server_info, string.format("name: %s", result.server_info.name))
        end
        if result.server_info.version then
          table.insert(endpoint_output.server_info, string.format("version: %s", result.server_info.version))
        end
        if result.server_info.protocolVersion then
          table.insert(endpoint_output.server_info, string.format("protocolVersion: %s", result.server_info.protocolVersion))
        end
      end

      -- Add tools list
      if #result.tools > 0 then
        endpoint_output.tools = result.tools
      end

      -- Add resources list
      if #result.resources > 0 then
        endpoint_output.resources = result.resources
      end

      -- Add prompts list
      if #result.prompts > 0 then
        endpoint_output.prompts = result.prompts
      end

      table.insert(endpoints_found, endpoint_output)
    end

    ::continue::
  end

  if #endpoints_found > 0 then
    output.endpoints = endpoints_found
    return output
  else
    return nil
  end
end
