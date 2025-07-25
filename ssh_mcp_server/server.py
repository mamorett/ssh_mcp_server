#!/usr/bin/env python3
"""
SSH MCP Server - Return content directly
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
                    "connection": {"type": "string", "description": "user@host:port"},
                    "command": {"type": "string", "description": "Command to execute"},
                    "private_key_path": {"type": "string", "description": "Path to SSH private key"}
                },
                "required": ["connection", "command"]
            }
        )
    ]

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]):
    """Handle tool calls - return content directly"""
    logger.info(f"Tool called: {name} with args: {arguments}")
    
    if name != "ssh_execute":
        return [TextContent(type="text", text=f"Unknown tool: {name}")]
    
    try:
        # Extract arguments
        connection = arguments["connection"]
        command = arguments["command"]
        private_key_path = arguments.get("private_key_path", "~/.ssh/id_rsa")
        
        # Parse connection string
        match = re.match(r'^(.+)@(.+):(\d+)$', connection)
        if not match:
            raise ValueError("Invalid connection format. Use: user@host:port")
        
        username, host, port = match.groups()
        port = int(port)
        
        # Load private key
        expanded_path = os.path.expanduser(private_key_path)
        if not os.path.exists(expanded_path):
            raise FileNotFoundError(f"Private key not found: {expanded_path}")
        
        with open(expanded_path, 'r') as f:
            key_content = f.read()
        
        key = asyncssh.import_private_key(key_content)
        
        # Execute SSH command
        async with asyncssh.connect(
            host=host,
            port=port,
            username=username,
            client_keys=[key],
            known_hosts=None,
            connect_timeout=30
        ) as conn:
            result = await asyncio.wait_for(
                conn.run(command, check=False),
                timeout=30
            )
            
            # Format output
            output = f"""SSH Command Execution:
Connection: {connection}
Command: {command}
Exit Code: {result.exit_status}

STDOUT:
{result.stdout or '(no output)'}

STDERR:
{result.stderr or '(no errors)'}"""
            
            return [TextContent(type="text", text=output)]
    
    except Exception as e:
        error_msg = f"SSH execution failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        
        return [TextContent(type="text", text=error_msg)]

async def main():
    """Main entry point"""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )

if __name__ == "__main__":
    asyncio.run(main())
