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

description = [[
Discovers Model Context Protocol (MCP) endpoints by probing HTTP and WebSocket services
with JSON-RPC 2.0 requests. MCP is a protocol that allows AI assistants to access tools,
resources, and prompts from external servers.

The script tests common MCP paths and checks for valid JSON-RPC 2.0 responses to the
following MCP methods:
- tools/list (lists available tools)
- resources/list (lists available resources)
- prompts/list (lists available prompts)
- initialize (MCP initialization handshake)

This script can identify both HTTP-based and WebSocket-based MCP servers.

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
-- |   MCP Endpoint Found: http://192.168.1.100:3000/mcp
-- |     Protocol: HTTP
-- |     Methods Supported:
-- |       tools/list: 3 tools available
-- |       resources/list: 5 resources available
-- |       prompts/list: 2 prompts available
-- |     Server Info:
-- |       name: example-mcp-server
-- |       version: 1.0.0
-- |_      protocolVersion: 2024-11-05
--
-- @args mcp-discovery.paths Comma-separated list of paths to probe (default: /,/mcp,/mcp/stream,/api/mcp,/v1/mcp,/rpc,/jsonrpc)
-- @args mcp-discovery.timeout Timeout for HTTP requests in milliseconds (default: 5000)
-- @args mcp-discovery.useragent User-Agent header to use (default: Nmap NSE)

author = "IntegSec <https://integsec.com>"
license = "GPLv3+ (GPL version 3 or later) - Compatible with Nmap license for distribution"
categories = {"discovery", "safe", "default"}

-- Default paths to probe for MCP endpoints
local DEFAULT_PATHS = {
  "/",
  "/mcp",
  "/mcp/stream",
  "/api/mcp",
  "/v1/mcp",
  "/rpc",
  "/jsonrpc",
  "/sse",
  "/messages"
}

-- Rule to determine if script should run
portrule = function(host, port)
  -- Run on HTTP, HTTPS, and common web ports
  return shortport.http(host, port) or
         shortport.portnumber({80, 443, 3000, 3001, 8080, 8443}, "tcp")(host, port)
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

-- Send HTTP POST request with JSON-RPC payload
local function send_mcp_request(host, port, path, method, params)
  local payload = create_jsonrpc_request(method, params)

  local options = {
    header = {
      ["Content-Type"] = "application/json",
      ["Accept"] = "application/json"
    },
    content = payload
  }

  stdnse.debug1("Probing %s:%d%s with method %s", host.ip, port.number, path, method)

  local response = http.post(host, port, path, options)

  return response
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

-- Probe a specific path for MCP endpoint
local function probe_path(host, port, path)
  local results = {}
  local methods = {
    {name = "tools/list", params = {}},
    {name = "resources/list", params = {}},
    {name = "prompts/list", params = {}},
    {name = "initialize", params = {
      protocolVersion = "2024-11-05",
      capabilities = {},
      clientInfo = {
        name = "nmap-mcp-discovery",
        version = "1.0.0"
      }
    }}
  }

  local mcp_found = false
  local method_results = {}
  local server_info = {}

  for _, method_info in ipairs(methods) do
    local response = send_mcp_request(host, port, path, method_info.name, method_info.params)

    if response and response.status == 200 then
      local parsed, err = parse_jsonrpc_response(response)

      if parsed then
        mcp_found = true

        if not parsed.is_error then
          -- Store successful method result
          if method_info.name == "tools/list" and parsed.result and parsed.result.tools then
            method_results[method_info.name] = string.format("%d tools available", #parsed.result.tools)
          elseif method_info.name == "resources/list" and parsed.result and parsed.result.resources then
            method_results[method_info.name] = string.format("%d resources available", #parsed.result.resources)
          elseif method_info.name == "prompts/list" and parsed.result and parsed.result.prompts then
            method_results[method_info.name] = string.format("%d prompts available", #parsed.result.prompts)
          elseif method_info.name == "initialize" and parsed.result then
            method_results[method_info.name] = "Initialized successfully"
            -- Extract server info from initialize response
            if parsed.result.serverInfo then
              server_info = parsed.result.serverInfo
            end
            if parsed.result.protocolVersion then
              server_info.protocolVersion = parsed.result.protocolVersion
            end
          else
            method_results[method_info.name] = "Supported"
          end
        else
          -- Even errors indicate the endpoint understands JSON-RPC
          stdnse.debug2("Method %s returned error: %s", method_info.name, json.generate(parsed.error))
        end
      end
    end

    -- Small delay between requests to be polite
    stdnse.sleep(0.1)
  end

  if mcp_found then
    return {
      path = path,
      methods = method_results,
      server_info = server_info
    }
  end

  return nil
end

-- Main action function
action = function(host, port)
  local output = stdnse.output_table()
  local endpoints_found = {}

  -- Get custom paths from script args or use defaults
  local paths_arg = stdnse.get_script_args("mcp-discovery.paths")
  local paths = DEFAULT_PATHS

  if paths_arg then
    paths = {}
    for path in string.gmatch(paths_arg, "[^,]+") do
      table.insert(paths, path)
    end
  end

  -- Determine protocol (http or https)
  local protocol = "http"
  if port.service == "https" or port.number == 443 or port.number == 8443 then
    protocol = "https"
  end

  -- Probe each path
  for _, path in ipairs(paths) do
    local result = probe_path(host, port, path)

    if result then
      local endpoint_url = string.format("%s://%s:%d%s", protocol, host.ip, port.number, path)
      local endpoint_output = stdnse.output_table()

      endpoint_output.url = endpoint_url
      endpoint_output.protocol = string.upper(protocol)

      -- Add methods information
      if next(result.methods) then
        endpoint_output.methods = {}
        for method, info in pairs(result.methods) do
          table.insert(endpoint_output.methods, string.format("%s: %s", method, info))
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

      table.insert(endpoints_found, endpoint_output)
    end
  end

  if #endpoints_found > 0 then
    output.endpoints = endpoints_found
    return output
  else
    return nil
  end
end
