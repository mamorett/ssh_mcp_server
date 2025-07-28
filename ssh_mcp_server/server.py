#!/usr/bin/env python3
"""
SSH MCP Server - Multi-server support with failover, SSH config support, and jump host support
Supports both ProxyJump and ProxyCommand configurations
"""

import asyncio
import logging
import os
import sys
import re
import asyncssh
import shlex
from typing import Any, Dict, List, Tuple, Optional
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger(__name__)

# Create server instance
server = Server("ssh-mcp-server")

class SSHConfigParser:
    """Enhanced SSH config parser with ProxyCommand and ProxyJump support"""
    
    def __init__(self, config_path: str = None):
        if config_path is None:
            config_path = os.path.expanduser("~/.ssh/config")
        self.config_path = config_path
        self.hosts = {}
        self._parse_config()
    
    def _parse_config(self):
        """Parse SSH config file"""
        if not os.path.exists(self.config_path):
            return
        
        try:
            with open(self.config_path, 'r') as f:
                content = f.read()
            
            lines = content.splitlines()
            current_hosts = []
            
            for line_num, line in enumerate(lines, 1):
                original_line = line
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Handle Host directive
                if line.lower().startswith('host '):
                    host_names = line[5:].strip().split()
                    current_hosts = []
                    for host_name in host_names:
                        # Skip wildcards but keep specific hosts
                        if '*' not in host_name and '?' not in host_name:
                            current_hosts.append(host_name)
                            if host_name not in self.hosts:
                                self.hosts[host_name] = {}
                
                # Handle configuration options
                elif current_hosts and ' ' in line:
                    # Split on first whitespace to handle values with spaces
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        key, value = parts
                        key = key.lower()
                        
                        # Store relevant configuration options
                        if key in ['hostname', 'user', 'port', 'identityfile', 'proxyjump', 'proxycommand']:
                            for host in current_hosts:
                                self.hosts[host][key] = value
            
        except Exception as e:
            logger.error(f"Failed to parse SSH config: {e}")
    
    def get_host_config(self, host: str) -> Dict[str, str]:
        """Get configuration for a specific host"""
        return self.hosts.get(host, {})
    
    def is_host_defined(self, host: str) -> bool:
        """Check if host is defined in SSH config"""
        return host in self.hosts
    
    def has_jump_host(self, host: str) -> bool:
        """Check if host uses a jump host (ProxyJump or ProxyCommand)"""
        config = self.get_host_config(host)
        return 'proxyjump' in config or 'proxycommand' in config
    
    def get_proxy_command(self, host: str) -> Optional[str]:
        """Get ProxyCommand for a host"""
        config = self.get_host_config(host)
        return config.get('proxycommand')
    
    def parse_proxy_command(self, proxy_command: str, target_host: str, target_port: int) -> Optional[Dict[str, Any]]:
        """Parse ProxyCommand to extract jump host information"""
        if not proxy_command:
            return None
        
        # Replace %h and %p placeholders
        command = proxy_command.replace('%h', target_host).replace('%p', str(target_port))
        
        # Try to parse common ProxyCommand patterns
        # Pattern: ssh user@jumphost nc %h %p
        # Pattern: ssh -p port user@jumphost nc %h %p
        ssh_nc_pattern = r'ssh\s+(?:-p\s+(\d+)\s+)?([^@]+@[^\s]+)\s+nc\s+'
        match = re.search(ssh_nc_pattern, command)
        
        if match:
            jump_port_str, jump_connection = match.groups()
            jump_port = int(jump_port_str) if jump_port_str else 22
            
            # Parse user@host
            if '@' in jump_connection:
                jump_user, jump_host = jump_connection.split('@', 1)
            else:
                jump_user = os.getenv('USER', 'root')
                jump_host = jump_connection
            
            return {
                'type': 'proxycommand',
                'host': jump_host,
                'username': jump_user,
                'port': jump_port,
                'command': command
            }
        
        # If we can't parse it, return the raw command
        logger.warning(f"Could not parse ProxyCommand: {proxy_command}")
        return {
            'type': 'proxycommand_raw',
            'command': command
        }
    
    def get_jump_host_config(self, host: str) -> Optional[Dict[str, Any]]:
        """Get jump host configuration for a host (ProxyJump or ProxyCommand)"""
        config = self.get_host_config(host)
        
        # Handle ProxyJump first (simpler)
        if 'proxyjump' in config:
            jump_spec = config['proxyjump']
            
            # Parse ProxyJump format: [user@]host[:port]
            if '@' in jump_spec:
                if ':' in jump_spec:
                    # user@host:port
                    match = re.match(r'^(.+)@(.+):(\d+)$', jump_spec)
                    if match:
                        jump_user, jump_host, jump_port = match.groups()
                        return {
                            'type': 'proxyjump',
                            'host': jump_host,
                            'username': jump_user,
                            'port': int(jump_port)
                        }
                else:
                    # user@host
                    match = re.match(r'^(.+)@(.+)$', jump_spec)
                    if match:
                        jump_user, jump_host = match.groups()
                        return {
                            'type': 'proxyjump',
                            'host': jump_host,
                            'username': jump_user,
                            'port': 22
                        }
            else:
                # just host or host:port
                if ':' in jump_spec:
                    jump_host, jump_port = jump_spec.split(':', 1)
                    return {
                        'type': 'proxyjump',
                        'host': jump_host,
                        'username': os.getenv('USER', 'root'),
                        'port': int(jump_port)
                    }
                else:
                    # Check if jump_spec is also a host in SSH config
                    if self.is_host_defined(jump_spec):
                        jump_config = self.get_host_config(jump_spec)
                        return {
                            'type': 'proxyjump',
                            'host': jump_config.get('hostname', jump_spec),
                            'username': jump_config.get('user', os.getenv('USER', 'root')),
                            'port': int(jump_config.get('port', 22))
                        }
                    else:
                        return {
                            'type': 'proxyjump',
                            'host': jump_spec,
                            'username': os.getenv('USER', 'root'),
                            'port': 22
                        }
        
        # Handle ProxyCommand
        if 'proxycommand' in config:
            proxy_command = config['proxycommand']
            
            # We need the target host and port to parse ProxyCommand properly
            target_host = config.get('hostname', host)
            target_port = int(config.get('port', 22))
            
            return self.parse_proxy_command(proxy_command, target_host, target_port)
        
        return None

# Global SSH config parser
ssh_config = SSHConfigParser()

@server.list_tools()
async def list_tools() -> List[Tool]:
    """List available tools"""
    return [
        Tool(
            name="ssh_execute",
            description="Execute a command on remote server(s) via SSH. Supports single server or list of servers with automatic failover. Can use SSH config entries with jump hosts (ProxyJump/ProxyCommand) - just provide the host name if defined in ~/.ssh/config.",
            inputSchema={
                "type": "object",
                "properties": {
                    "connection": {
                        "oneOf": [
                            {"type": "string", "description": "Single SSH connection: user@host:port, user@host, or just host (if in SSH config)"},
                            {"type": "array", "items": {"type": "string"}, "description": "List of SSH connections: [user@host1:port, host2, ...]"}
                        ],
                        "description": "SSH connection string(s). Format: user@host:port, user@host, or just hostname (if defined in ~/.ssh/config). Supports jump hosts via SSH config (ProxyJump/ProxyCommand)."
                    },
                    "command": {
                        "type": "string",
                        "description": "Command to execute on the remote server(s)"
                    },
                    "private_key_path": {
                        "type": "string",
                        "description": "Path to SSH private key file (default: ~/.ssh/id_rsa, or from SSH config)"
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
            description="Test SSH connection to remote server(s). Supports single server or list of servers. Can use SSH config entries with jump hosts (ProxyJump/ProxyCommand).",
            inputSchema={
                "type": "object",
                "properties": {
                    "connection": {
                        "oneOf": [
                            {"type": "string", "description": "Single SSH connection: user@host:port, user@host, or just host (if in SSH config)"},
                            {"type": "array", "items": {"type": "string"}, "description": "List of SSH connections: [user@host1:port, host2, ...]"}
                        ],
                        "description": "SSH connection string(s). Format: user@host:port, user@host, or just hostname (if defined in ~/.ssh/config). Supports jump hosts via SSH config (ProxyJump/ProxyCommand)."
                    },
                    "private_key_path": {
                        "type": "string",
                        "description": "Path to SSH private key file (default: ~/.ssh/id_rsa, or from SSH config)"
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
            description="Execute different commands on different servers in batch mode. Can use SSH config entries with jump hosts (ProxyJump/ProxyCommand).",
            inputSchema={
                "type": "object",
                "properties": {
                    "servers": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "connection": {"type": "string", "description": "SSH connection: user@host:port, user@host, or just host (if in SSH config)"},
                                "command": {"type": "string", "description": "Command to execute"},
                                "name": {"type": "string", "description": "Optional server name/label"}
                            },
                            "required": ["connection", "command"]
                        },
                        "description": "List of server/command pairs"
                    },
                    "private_key_path": {
                        "type": "string",
                        "description": "Path to SSH private key file (default: ~/.ssh/id_rsa, or from SSH config)"
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
        ),
        Tool(
            name="ssh_list_config_hosts",
            description="List all hosts defined in SSH config file (~/.ssh/config) including jump host information (ProxyJump/ProxyCommand)",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="ssh_debug_config",
            description="Debug SSH config parsing for a specific host",
            inputSchema={
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Host name to debug"
                    }
                },
                "required": ["host"]
            }
        )
    ]

def parse_connection(connection: str) -> Tuple[str, str, int, str]:
    """Parse SSH connection string with SSH config support"""
    
    # Check if it's just a hostname (SSH config entry)
    if '@' not in connection and ':' not in connection:
        # This might be a SSH config host
        if ssh_config.is_host_defined(connection):
            host_config = ssh_config.get_host_config(connection)
            hostname = host_config.get('hostname', connection)
            username = host_config.get('user', os.getenv('USER', 'root'))
            port = int(host_config.get('port', 22))
            return username, hostname, port, connection
        else:
            raise ValueError(f"Host '{connection}' not found in SSH config and no user specified. Use user@host format or add to ~/.ssh/config")
    
    # Parse traditional formats
    if ':' in connection:
        match = re.match(r'^(.+)@(.+):(\d+)$', connection)
        if not match:
            raise ValueError("Invalid format. Use: user@host:port, user@host, or hostname (if in SSH config)")
        username, host, port_str = match.groups()
        port = int(port_str)
    else:
        match = re.match(r'^(.+)@(.+)$', connection)
        if not match:
            raise ValueError("Invalid format. Use: user@host:port, user@host, or hostname (if in SSH config)")
        username, host = match.groups()
        port = 22
    
    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535")
    
    return username, host, port, connection

def get_ssh_key(private_key_path: str = None, private_key_content: str = None, config_host: str = None):
    """Get SSH private key from path, content, or SSH config"""
    if private_key_content:
        return asyncssh.import_private_key(private_key_content)
    
    # Check SSH config for identity file
    if config_host and ssh_config.is_host_defined(config_host):
        host_config = ssh_config.get_host_config(config_host)
        if 'identityfile' in host_config:
            private_key_path = host_config['identityfile']
    
    if not private_key_path:
        private_key_path = "~/.ssh/id_rsa"
    
    expanded_path = os.path.expanduser(private_key_path)
    
    if not os.path.exists(expanded_path):
        raise FileNotFoundError(f"Private key file not found: {expanded_path}")
    
    with open(expanded_path, 'r') as f:
        key_content = f.read()
    
    return asyncssh.import_private_key(key_content)

async def create_ssh_connection(host: str, port: int, username: str, key, connect_timeout: int, original_connection: str):
    """Create SSH connection with ProxyJump and ProxyCommand support"""
    
    # Check if this is a config host that needs a jump host
    if ssh_config.is_host_defined(original_connection) and ssh_config.has_jump_host(original_connection):
        jump_config = ssh_config.get_jump_host_config(original_connection)
        
        if jump_config:
            if jump_config['type'] == 'proxyjump':
                # Handle ProxyJump - direct SSH tunnel
                try:
                    # First connect to jump host
                    jump_conn = await asyncssh.connect(
                        host=jump_config['host'],
                        port=jump_config['port'],
                        username=jump_config['username'],
                        client_keys=[key],
                        known_hosts=None,
                        connect_timeout=connect_timeout
                    )
                    
                    # Then connect to target host through jump host
                    target_conn = await jump_conn.connect_ssh(
                        host=host,
                        port=port,
                        username=username,
                        client_keys=[key],
                        known_hosts=None
                    )
                    
                    return target_conn, jump_conn
                    
                except Exception as e:
                    logger.error(f"Failed to connect through ProxyJump: {e}")
                    raise
            
            elif jump_config['type'] == 'proxycommand':
                # Handle ProxyCommand - use asyncssh's tunnel support
                try:
                    # First connect to the jump host
                    jump_conn = await asyncssh.connect(
                        host=jump_config['host'],
                        port=jump_config['port'],
                        username=jump_config['username'],
                        client_keys=[key],
                        known_hosts=None,
                        connect_timeout=connect_timeout
                    )
                    
                    # Create tunnel through jump host
                    target_conn = await jump_conn.connect_ssh(
                        host=host,
                        port=port,
                        username=username,
                        client_keys=[key],
                        known_hosts=None
                    )
                    
                    return target_conn, jump_conn
                    
                except Exception as e:
                    logger.error(f"Failed to connect through ProxyCommand: {e}")
                    raise
            
            elif jump_config['type'] == 'proxycommand_raw':
                # For complex ProxyCommands we can't parse, fall back to direct connection
                # and let the user know
                logger.warning(f"Complex ProxyCommand not supported, attempting direct connection: {jump_config['command']}")
                raise ValueError(f"Complex ProxyCommand not supported: {jump_config['command']}")
    
    # Direct connection (no jump host)
    conn = await asyncssh.connect(
        host=host,
        port=port,
        username=username,
        client_keys=[key],
        known_hosts=None,
        connect_timeout=connect_timeout
    )
    
    return conn, None

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
    jump_conn = None
    try:
        username, host, port, original_connection = parse_connection(connection)
        
        conn, jump_conn = await create_ssh_connection(host, port, username, key, connect_timeout, original_connection)
        
        try:
            server_info = await conn.run('uname -a', check=False)
            uptime_info = await conn.run('uptime', check=False)
            
            config_info = ""
            if ssh_config.is_host_defined(original_connection):
                config_info = " (from SSH config"
                if ssh_config.has_jump_host(original_connection):
                    jump_config = ssh_config.get_jump_host_config(original_connection)
                    if jump_config:
                        config_info += f" with {jump_config['type']}"
                config_info += ")"
            
            result = f"""✅ {connection} - SUCCESS{config_info}
Actual connection: {username}@{host}:{port}
Server: {server_info.stdout.strip() if server_info.stdout else 'N/A'}
Uptime: {uptime_info.stdout.strip() if uptime_info.stdout else 'N/A'}"""
            
            return connection, True, result
        finally:
            conn.close()
            if jump_conn:
                jump_conn.close()
    
    except Exception as e:
        if jump_conn:
            jump_conn.close()
        result = f"❌ {connection} - FAILED: {str(e)}"
        return connection, False, result

async def execute_single_command(connection: str, command: str, key, timeout: int, connect_timeout: int, server_name: str = None) -> Tuple[str, bool, str]:
    """Execute command on a single server"""
    display_name = server_name or connection
    jump_conn = None
    
    try:
        username, host, port, original_connection = parse_connection(connection)
        
        conn, jump_conn = await create_ssh_connection(host, port, username, key, connect_timeout, original_connection)
        
        try:
            result = await asyncio.wait_for(
                conn.run(command, check=False),
                timeout=timeout
            )
            
            success = result.exit_status == 0
            status_emoji = "✅" if success else "❌"
            
            config_info = ""
            if ssh_config.is_host_defined(original_connection):
                config_info = " (from SSH config"
                if ssh_config.has_jump_host(original_connection):
                    jump_config = ssh_config.get_jump_host_config(original_connection)
                    if jump_config:
                        config_info += f" with {jump_config['type']}"
                config_info += ")"
            
            output = f"""{status_emoji} {display_name}{config_info}
Connection: {connection} → {username}@{host}:{port}
Command: {command}
Exit Code: {result.exit_status}

STDOUT:
{result.stdout if result.stdout else '(no output)'}

STDERR:
{result.stderr if result.stderr else '(no errors)'}"""
            
            return connection, success, output
        finally:
            conn.close()
            if jump_conn:
                jump_conn.close()
    
    except asyncio.TimeoutError:
        if jump_conn:
            jump_conn.close()
        output = f"""⏰ {display_name} - TIMEOUT
Connection: {connection}
Command: {command}
Timeout: {timeout}s"""
        return connection, False, output
    
    except Exception as e:
        if jump_conn:
            jump_conn.close()
        output = f"""❌ {display_name} - FAILED
Connection: {connection}
Command: {command}
Error: {str(e)}"""
        return connection, False, output

@server.call_tool()
async def call_tool(name: str, arguments: Dict[str, Any]):
    """Handle tool calls"""
    
    if name == "ssh_execute":
        return await execute_ssh_command(arguments)
    elif name == "ssh_test_connection":
        return await test_ssh_connection(arguments)
    elif name == "ssh_execute_batch":
        return await execute_ssh_batch(arguments)
    elif name == "ssh_list_config_hosts":
        return await list_ssh_config_hosts(arguments)
    elif name == "ssh_debug_config":
        return await debug_ssh_config(arguments)
    else:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

async def debug_ssh_config(args: Dict[str, Any]):
    """Debug SSH config parsing for a specific host"""
    try:
        host = args["host"]
        
        output_lines = [f"SSH Config Debug for '{host}':\n"]
        
        # Check if host is defined
        is_defined = ssh_config.is_host_defined(host)
        output_lines.append(f"Host defined in SSH config: {is_defined}")
        
        if is_defined:
            config = ssh_config.get_host_config(host)
            output_lines.append(f"Raw config: {config}")
            
            # Parse connection details
            try:
                username, hostname, port, original = parse_connection(host)
                output_lines.append(f"Parsed connection: {username}@{hostname}:{port}")
            except Exception as e:
                output_lines.append(f"Failed to parse connection: {e}")
            
            # Check jump host
            has_jump = ssh_config.has_jump_host(host)
            output_lines.append(f"Has jump host: {has_jump}")
            
            if has_jump:
                jump_config = ssh_config.get_jump_host_config(host)
                output_lines.append(f"Jump host config: {jump_config}")
                
                if jump_config and jump_config['type'] == 'proxycommand':
                    output_lines.append(f"ProxyCommand: {config.get('proxycommand', 'N/A')}")
        
        # Show all available hosts
        all_hosts = list(ssh_config.hosts.keys())
        output_lines.append(f"\nAll available hosts: {all_hosts}")
        
        return [TextContent(type="text", text="\n".join(output_lines))]
    
    except Exception as e:
        error_msg = f"Failed to debug SSH config: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [TextContent(type="text", text=error_msg)]

async def list_ssh_config_hosts(args: Dict[str, Any]):
    """List all hosts defined in SSH config"""
    try:
        if not ssh_config.hosts:
            return [TextContent(type="text", text="No hosts found in SSH config (~/.ssh/config)")]
        
        output_lines = ["SSH Config Hosts:\n"]
        
        for host, config in ssh_config.hosts.items():
            hostname = config.get('hostname', host)
            user = config.get('user', 'default')
            port = config.get('port', '22')
            identity = config.get('identityfile', 'default')
            
            output_lines.append(f"🖥️  {host}")
            output_lines.append(f"   Hostname: {hostname}")
            output_lines.append(f"   User: {user}")
            output_lines.append(f"   Port: {port}")
            output_lines.append(f"   Identity: {identity}")
            
            # Show jump host info if present
            if ssh_config.has_jump_host(host):
                jump_config = ssh_config.get_jump_host_config(host)
                if jump_config:
                    if jump_config['type'] == 'proxyjump':
                        output_lines.append(f"   🔗 ProxyJump: {jump_config['username']}@{jump_config['host']}:{jump_config['port']}")
                    elif jump_config['type'] == 'proxycommand':
                        output_lines.append(f"   🔗 ProxyCommand: {config.get('proxycommand', 'N/A')}")
                        output_lines.append(f"   🔗 Jump Host: {jump_config['username']}@{jump_config['host']}:{jump_config['port']}")
                    elif jump_config['type'] == 'proxycommand_raw':
                        output_lines.append(f"   🔗 ProxyCommand (unparsed): {config.get('proxycommand', 'N/A')}")
                elif 'proxyjump' in config:
                    output_lines.append(f"   🔗 ProxyJump: {config['proxyjump']}")
                elif 'proxycommand' in config:
                    output_lines.append(f"   🔗 ProxyCommand: {config['proxycommand']}")
            
            output_lines.append("")
        
        output_lines.append(f"Total: {len(ssh_config.hosts)} hosts configured")
        
        return [TextContent(type="text", text="\n".join(output_lines))]
    
    except Exception as e:
        error_msg = f"Failed to list SSH config hosts: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [TextContent(type="text", text=error_msg)]

async def test_ssh_connection(args: Dict[str, Any]):
    """Test SSH connection(s)"""
    try:
        connections = normalize_connections(args["connection"])
        private_key_path = args.get("private_key_path")
        private_key_content = args.get("private_key_content")
        connect_timeout = args.get("connect_timeout", 30)
        parallel = args.get("parallel", False)
        
        # Get private key (try to use SSH config for the first connection if applicable)
        config_host = connections[0] if len(connections) == 1 and '@' not in connections[0] else None
        key = get_ssh_key(private_key_path, private_key_content, config_host)
        
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
        
        # Get private key (try to use SSH config for the first connection if applicable)
        config_host = connections[0] if len(connections) == 1 and '@' not in connections[0] else None
        key = get_ssh_key(private_key_path, private_key_content, config_host)
        
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
        
        # Get private key (try to use SSH config for the first server if applicable)
        config_host = servers[0]["connection"] if len(servers) == 1 and '@' not in servers[0]["connection"] else None
        key = get_ssh_key(private_key_path, private_key_content, config_host)
        
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
        
        final_output = header + "\n" + "="*80 + "\n\n" + "\n\n".join(results) + summary
        
        return [TextContent(type="text", text=final_output)]
    
    except Exception as e:
        error_msg = f"SSH batch execution failed: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return [TextContent(type="text", text=error_msg)]

def main():
    """Main entry point for the CLI script"""
    asyncio.run(async_main())

async def async_main():
    """Async main entry point"""
    async with stdio_server() as streams:
        await server.run(
            streams[0], streams[1], server.create_initialization_options()
        )

if __name__ == "__main__":
    main()
