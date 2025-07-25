#!/usr/bin/env python3
"""
SSH MCP Server - Multi-server support with failover
"""

import asyncio
import logging
import os
import sys
import re
import asyncssh
from typing import Any, Dict, List, Tuple, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)
logger = logging.getLogger(__name__)

# Create server instance
server = Server("ssh-mcp-server")

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools"""
    return [
        Tool(
            name="ssh_execute",
            description="Execute a command on remote server(s) via SSH. Supports single server or list of servers with automatic failover.",
            inputSchema={
                "type": "object",
                "properties": {
                    "connection": {
                        "oneOf": [
                            {"type": "string", "description": "Single SSH connection: user@host:port"},
                            {"type": "array", "items": {"type": "string"}, "description": "List of SSH connections: [user@host1:port, user@host2:port, ...]"}
                        ],
                        "description": "SSH connection string(s) in format: user@host:port or user@host"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute on the remote server(s)"
                    },
                    "private_key_path": {
                        "type": "string",
                        "description": "Path to SSH private key file (default: ~/.ssh/id_rsa)",
                        "default": "~/.ssh/id_rsa"
                    },
                    "private_key_content": {
                        "type": "string",
                        "description": "SSH private key content as string (alternative to private_key_path)"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Command timeout in seconds (default: 30)",
                        "default": 30,
                        "minimum": 1,
                        "maximum": 300
                    },
                    "connect_timeout": {
                        "type": "integer", 
                        "description": "Connection timeout in seconds (default: 30)",
                        "default": 30,
                        "minimum": 1,
                        "maximum": 60
                    },
                    "fail_fast": {
                        "type": "boolean",
                        "description": "Stop on first failure (default: false - continue with other servers)",
                        "default": False
                    },
                    "parallel": {
                        "type": "boolean",
                        "description": "Execute on all servers in parallel (default: false - sequential)",
                        "default": False
                    }
                },
                "required": ["connection", "command"]
            }
        ),
        Tool(
            name="ssh_test_connection",
            description="Test SSH connection to remote server(s). Supports single server or list of servers.",
            inputSchema={
                "type": "object",
                "properties": {
                    "connection": {
                        "oneOf": [
                            {"type": "string", "description": "Single SSH connection: user@host:port"},
                            {"type": "array", "items": {"type": "string"}, "description": "List of SSH connections: [user@host1:port, user@host2:port, ...]"}
                        ],
                        "description": "SSH connection string(s) in format: user@host:port or user@host"
                    },
                    "private_key_path": {
                        "type": "string",
                        "description": "Path to SSH private key file (default: ~/.ssh/id_rsa)",
                        "default": "~/.ssh/id_rsa"
                    },
                    "private_key_content": {
                        "type": "string",
                        "description": "SSH private key content as string (alternative to private_key_path)"
                    },
                    "connect_timeout": {
                        "type": "integer",
                        "description": "Connection timeout in seconds (default: 30)",
                        "default": 30,
                        "minimum": 1,
                        "maximum": 60
                    },
                    "parallel": {
                        "type": "boolean",
                        "description": "Test all servers in parallel (default: false - sequential)",
                        "default": False
                    }
                },
                "required": ["connection"]
            }
        ),
        Tool(
            name="ssh_execute_batch",
            description="Execute different commands on different servers in batch mode.",
            inputSchema={
                "type": "object",
                "properties": {
                    "servers": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "connection": {"type": "string", "description": "SSH connection: user@host:port"},
                                "command": {"type": "string", "description": "Command to execute"},
                                "name": {"type": "string", "description": "Optional server name/label"}
                            },
                            "required": ["connection", "command"]
                        },
                        "description": "List of server/command pairs"
                    },
                    "private_key_path": {
                        "type": "string",
                        "description": "Path to SSH private key file (default: ~/.ssh/id_rsa)",
                        "default": "~/.ssh/id_rsa"
                    },
                    "private_key_content": {
                        "type": "string",
                        "description": "SSH private key content as string"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Command timeout in seconds (default: 30)",
                        "default": 30
                    },
                    "connect_timeout": {
                        "type": "integer",
                        "description": "Connection timeout in seconds (default: 30)",
                        "default": 30
                    },
                    "parallel": {
                        "type": "boolean",
                        "description": "Execute all in parallel (default: true)",
                        "default": True
                    },
                    "fail_fast": {
                        "type": "boolean",
                        "description": "Stop on first failure (default: false)",
                        "default": False
                    }
                },
                "required": ["servers"]
            }
        )
    ]

def parse_connection(connection: str) -> Tuple[str, str, int]:
    """Parse SSH connection string"""
    logger.debug(f"Parsing connection: {connection}")
    
    if ':' in connection:
        match = re.match(r'^(.+)@(.+):(\d+)$', connection)
        if not match:
            raise ValueError("Invalid format. Use: user@host:port or user@host")
        username, host, port_str = match.groups()
        port = int(port_str)
    else:
        match = re.match(r'^(.+)@(.+)$', connection)
        if not match:
            raise ValueError("Invalid format. Use: user@host:port or user@host")
        username, host = match.groups()
        port = 22
    
    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535")
    
    logger.debug(f"Parsed connection: {username}@{host}:{port}")
    return username, host, port

def get_ssh_key(private_key_path: str = None, private_key_content: str = None):
    """Get SSH private key from path or content"""
    if private_key_content:
        logger.debug("Using private key from content")
        return asyncssh.import_private_key(private_key_content)
    
    if not private_key_path:
        private_key_path = "~/.ssh/id_rsa"
    
    expanded_path = os.path.expanduser(private_key_path)
    logger.debug(f"Reading private key from: {expanded_path}")
    
    if not os.path.exists(expanded_path):
        raise FileNotFoundError(f"Private key file not found: {expanded_path}")
    
    with open(expanded_path, 'r') as f:
        key_content = f.read()
    
    return asyncssh.import_private_key(key_content)

def normalize_connections(connection) -> List[str]:
    """Normalize connection input to list of strings"""
    if isinstance(connection, str):
        return [connection]
    elif isinstance(connection, list):
        return connection
    else:
        raise ValueError("Connection must be string or list of strings")

async def test_single_connection(connection: str, key, connect_timeout: int) -> Tuple[str, bool, str]:
    """Test a single SSH connection"""
    try:
        username, host, port = parse_connection(connection)
        
        async with asyncssh.connect(
            host=host,
            port=port,
            username=username,
            client_keys=[key],
            known_hosts=None,
            connect_timeout=connect_timeout
        ) as conn:
            server_info = await conn.run('uname -a', check=False)
            uptime_info = await conn.run('uptime', check=False)
            
            result = f"""✅ {connection} - SUCCESS
Server: {server_info.stdout.strip() if server_info.stdout else 'N/A'}
Uptime: {uptime_info.stdout.strip() if uptime_info.stdout else 'N/A'}"""
            
            return connection, True, result
    
    except Exception as e:
        result = f"❌ {connection} - FAILED: {str(e)}"
        return connection, False, result

async def execute_single_command(connection: str, command: str, key, timeout: int, connect_timeout: int, server_name: str = None) -> Tuple[str, bool, str]:
    """Execute command on a single server"""
    display_name = server_name or connection
    
    try:
        username, host, port = parse_connection(connection)
        
        async with asyncssh.connect(
            host=host,
            port=port,
            username=username,
            client_keys=[key],
            known_hosts=None,
            connect_timeout=connect_timeout
        ) as conn:
            result = await asyncio.wait_for(
                conn.run(command, check=False),
                timeout=timeout
            )
            
            success = result.exit_status == 0
            status_emoji = "✅" if success else "❌"
            
            output = f"""{status_emoji} {display_name}
Connection: {connection}
Command: {command}
Exit Code: {result.exit_status}

STDOUT:
{result.stdout if result.stdout else '(no output)'}

STDERR:
{result.stderr if result.stderr else '(no errors)'}"""
            
            return connection, success, output
    
    except asyncio.TimeoutError:
        output = f"""⏰ {display_name} - TIMEOUT
Connection: {connection}
Command: {command}
Timeout: {timeout}s"""
        return connection, False, output
    
    except Exception as e:
        output = f"""❌ {display_name} - FAILED
Connection: {connection}
Command: {command}
Error: {str(e)}"""
        return connection, False, output

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]):
    """Handle tool calls"""
    logger.info(f"Tool called: {name} with args: {list(arguments.keys())}")
    
    if name == "ssh_execute":
        return await execute_ssh_command(arguments)
    elif name == "ssh_test_connection":
        return await test_ssh_connection(arguments)
    elif name == "ssh_execute_batch":
        return await execute_ssh_batch(arguments)
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

async def test_ssh_connection(args: Dict[str, Any]):
    """Test SSH connection(s)"""
    try:
        connections = normalize_connections(args["connection"])
        private_key_path = args.get("private_key_path")
        private_key_content = args.get("private_key_content")
        connect_timeout = args.get("connect_timeout", 30)
        parallel = args.get("parallel", False)
        
        logger.info(f"Testing {len(connections)} connection(s)")
        
        # Get private key
        key = get_ssh_key(private_key_path, private_key_content)
        
        # Test connections
        if parallel:
            tasks = [test_single_connection(conn, key, connect_timeout) for conn in connections]
            results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            results = []
            for conn in connections:
                result = await test_single_connection(conn, key, connect_timeout)
                results.append(result)
        
        # Format results
        successful = 0
        failed = 0
        output_lines = [f"SSH Connection Test Results ({len(connections)} servers):\n"]
        
        for result in results:
            if isinstance(result, Exception):
                output_lines.append(f"❌ ERROR: {str(result)}")
                failed += 1
            else:
                conn, success, output = result
                output_lines.append(output)
                if success:
                    successful += 1
                else:
                    failed += 1
        
        summary = f"\n📊 Summary: {successful} successful, {failed} failed"
        output_lines.append(summary)
        
        return [TextContent(type="text", text="\n\n".join(output_lines))]
    
    except Exception as e:
        error_msg = f"Connection test failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [TextContent(type="text", text=error_msg)]

async def execute_ssh_command(args: Dict[str, Any]):
    """Execute SSH command on multiple servers"""
    try:
        connections = normalize_connections(args["connection"])
        command = args["command"]
        private_key_path = args.get("private_key_path")
        private_key_content = args.get("private_key_content")
        timeout = args.get("timeout", 30)
        connect_timeout = args.get("connect_timeout", 30)
        fail_fast = args.get("fail_fast", False)
        parallel = args.get("parallel", False)
        
        logger.info(f"Executing command on {len(connections)} server(s)")
        
        # Get private key
        key = get_ssh_key(private_key_path, private_key_content)
        
        # Execute commands
        results = []
        successful = 0
        failed = 0
        
        if parallel:
            tasks = [execute_single_command(conn, command, key, timeout, connect_timeout) for conn in connections]
            task_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in task_results:
                if isinstance(result, Exception):
                    results.append(f"❌ ERROR: {str(result)}")
                    failed += 1
                else:
                    conn, success, output = result
                    results.append(output)
                    if success:
                        successful += 1
                    else:
                        failed += 1
        else:
            for conn in connections:
                try:
                    conn, success, output = await execute_single_command(conn, command, key, timeout, connect_timeout)
                    results.append(output)
                    
                    if success:
                        successful += 1
                    else:
                        failed += 1
                        if fail_fast:
                            results.append(f"\n🛑 Stopping execution due to failure (fail_fast=true)")
                            break
                            
                except Exception as e:
                    error_output = f"❌ {conn} - EXCEPTION: {str(e)}"
                    results.append(error_output)
                    failed += 1
                    if fail_fast:
                        results.append(f"\n🛑 Stopping execution due to exception (fail_fast=true)")
                        break
        
        # Format final output
        header = f"SSH Command Execution Results ({len(connections)} servers):\nCommand: {command}\n"
        summary = f"\n📊 Summary: {successful} successful, {failed} failed"
        
        final_output = header + "\n" + "="*80 + "\n\n" + "\n\n".join(results) + summary
        
        return [TextContent(type="text", text=final_output)]
    
    except Exception as e:
        error_msg = f"SSH execution failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [TextContent(type="text", text=error_msg)]

async def execute_ssh_batch(args: Dict[str, Any]):
    """Execute different commands on different servers"""
    try:
        servers = args["servers"]
        private_key_path = args.get("private_key_path")
        private_key_content = args.get("private_key_content")
        timeout = args.get("timeout", 30)
        connect_timeout = args.get("connect_timeout", 30)
        parallel = args.get("parallel", True)
        fail_fast = args.get("fail_fast", False)
        
        logger.info(f"Executing batch commands on {len(servers)} server(s)")
        
        # Get private key
        key = get_ssh_key(private_key_path, private_key_content)
        
        # Execute commands
        results = []
        successful = 0
        failed = 0
        
        if parallel:
            tasks = []
            for server in servers:
                task = execute_single_command(
                    server["connection"], 
                    server["command"], 
                    key, 
                    timeout, 
                    connect_timeout,
                    server.get("name")
                )
                tasks.append(task)
            
            task_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in task_results:
                if isinstance(result, Exception):
                    results.append(f"❌ ERROR: {str(result)}")
                    failed += 1
                else:
                    conn, success, output = result
                    results.append(output)
                    if success:
                        successful += 1
                    else:
                        failed += 1
        else:
            for server in servers:
                try:
                    conn, success, output = await execute_single_command(
                        server["connection"], 
                        server["command"], 
                        key, 
                        timeout, 
                        connect_timeout,
                        server.get("name")
                    )
                    results.append(output)
                    
                    if success:
                        successful += 1
                    else:
                        failed += 1
                        if fail_fast:
                            results.append(f"\n🛑 Stopping batch execution due to failure (fail_fast=true)")
                            break
                            
                except Exception as e:
                    error_output = f"❌ {server['connection']} - EXCEPTION: {str(e)}"
                    results.append(error_output)
                    failed += 1
                    if fail_fast:
                        results.append(f"\n🛑 Stopping batch execution due to exception (fail_fast=true)")
                        break
        
        # Format final output
        header = f"SSH Batch Execution Results ({len(servers)} servers):\n"
        summary = f"\n📊 Summary: {successful} successful, {failed} failed"
        
        final_output = header + "="*80 + "\n\n" + "\n\n".join(results) + summary
        
        return [TextContent(type="text", text=final_output)]
    
    except Exception as e:
        error_msg = f"SSH batch execution failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [TextContent(type="text", text=error_msg)]

async def main():
    """Main entry point"""
    logger.info("Starting SSH MCP Server with multi-server support")
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)
