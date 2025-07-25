#!/usr/bin/env python3
"""
SSH MCP Server - Complete version with all features
"""

import asyncio
import logging
import os
import sys
import re
import asyncssh
from typing import Any, Dict, List

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
            description="Execute a command on a remote server via SSH",
            inputSchema={
                "type": "object",
                "properties": {
                    "connection": {
                        "type": "string", 
                        "description": "SSH connection string in format: user@host:port"
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute on the remote server"
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
                    }
                },
                "required": ["connection", "command"]
            }
        ),
        Tool(
            name="ssh_test_connection",
            description="Test SSH connection to a remote server",
            inputSchema={
                "type": "object",
                "properties": {
                    "connection": {
                        "type": "string",
                        "description": "SSH connection string in format: user@host:port"
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
                    }
                },
                "required": ["connection"]
            }
        )
    ]

def parse_connection(connection: str) -> tuple[str, str, int]:
    """Parse SSH connection string"""
    logger.debug(f"Parsing connection: {connection}")
    
    # Support both user@host:port and user@host formats
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
        port = 22  # Default SSH port
    
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

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]):
    """Handle tool calls"""
    logger.info(f"Tool called: {name} with args: {list(arguments.keys())}")
    
    if name == "ssh_execute":
        return await execute_ssh_command(arguments)
    elif name == "ssh_test_connection":
        return await test_ssh_connection(arguments)
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

async def test_ssh_connection(args: Dict[str, Any]):
    """Test SSH connection"""
    try:
        connection = args["connection"]
        private_key_path = args.get("private_key_path")
        private_key_content = args.get("private_key_content")
        connect_timeout = args.get("connect_timeout", 30)
        
        logger.info(f"Testing connection to: {connection}")
        
        # Parse connection
        username, host, port = parse_connection(connection)
        
        # Get private key
        key = get_ssh_key(private_key_path, private_key_content)
        
        # Test connection
        async with asyncssh.connect(
            host=host,
            port=port,
            username=username,
            client_keys=[key],
            known_hosts=None,
            connect_timeout=connect_timeout
        ) as conn:
            # Get server info
            server_info = await conn.run('uname -a', check=False)
            uptime_info = await conn.run('uptime', check=False)
            
            output = f"""SSH Connection Test: SUCCESS
Connection: {connection}
Server: {username}@{host}:{port}
Connection Time: {connect_timeout}s timeout

Server Information:
{server_info.stdout.strip() if server_info.stdout else 'N/A'}

Uptime:
{uptime_info.stdout.strip() if uptime_info.stdout else 'N/A'}

✅ Connection established successfully!"""
            
            return [TextContent(type="text", text=output)]
    
    except Exception as e:
        error_msg = f"""SSH Connection Test: FAILED
Connection: {args.get('connection', 'N/A')}
Error: {str(e)}

❌ Connection failed. Please check:
- Host and port are correct
- SSH service is running on the target
- Private key is valid and has proper permissions
- Network connectivity to the host"""
        
        logger.error(f"Connection test failed: {e}", exc_info=True)
        return [TextContent(type="text", text=error_msg)]

async def execute_ssh_command(args: Dict[str, Any]):
    """Execute SSH command"""
    try:
        connection = args["connection"]
        command = args["command"]
        private_key_path = args.get("private_key_path")
        private_key_content = args.get("private_key_content")
        timeout = args.get("timeout", 30)
        connect_timeout = args.get("connect_timeout", 30)
        
        logger.info(f"Executing command on {connection}: {command}")
        
        # Parse connection
        username, host, port = parse_connection(connection)
        
        # Get private key
        key = get_ssh_key(private_key_path, private_key_content)
        
        # Execute command
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
            
            # Determine success
            success = result.exit_status == 0
            status_emoji = "✅" if success else "❌"
            
            # Format output
            output = f"""SSH Command Execution {status_emoji}
Connection: {connection}
Command: {command}
Exit Code: {result.exit_status}
Success: {success}
Execution Time: <{timeout}s

STDOUT:
{result.stdout if result.stdout else '(no output)'}

STDERR:
{result.stderr if result.stderr else '(no errors)'}"""
            
            return [TextContent(type="text", text=output)]
    
    except asyncio.TimeoutError:
        error_msg = f"""SSH Command Execution ⏰ TIMEOUT
Connection: {connection}
Command: {command}
Timeout: {timeout}s

The command exceeded the timeout limit of {timeout} seconds.
Consider increasing the timeout or checking if the command is hanging."""
        
        logger.error(f"Command timeout: {command}")
        return [TextContent(type="text", text=error_msg)]
    
    except Exception as e:
        error_msg = f"""SSH Command Execution ❌ FAILED
Connection: {args.get('connection', 'N/A')}
Command: {args.get('command', 'N/A')}
Error: {str(e)}

Please check:
- Connection parameters are correct
- SSH key is valid and accessible
- Target server is reachable
- Command syntax is correct"""
        
        logger.error(f"SSH execution failed: {e}", exc_info=True)
        return [TextContent(type="text", text=error_msg)]

async def main():
    """Main entry point"""
    logger.info("Starting SSH MCP Server")
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
