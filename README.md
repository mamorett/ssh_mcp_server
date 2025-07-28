# SSH MCP Server (Python)

An MCP (Model Context Protocol) server that enables remote command execution via SSH, implemented in Python.

## Features

- Execute commands on remote servers via SSH
- Support for private key authentication with optional passphrases
- Configurable timeouts
- Detailed output including stdout, stderr, and exit codes
- Comprehensive error handling and validation
- Two implementations: asyncssh (recommended) and Paramiko

## Installation

This section covers how to install and configure the SSH MCP Server for use with MCP-compatible clients.

### Prerequisites

*   Python 3.8 or higher
*   uv package manager
*   An MCP-compatible client (e.g., Claude Desktop)

### Standard Installation

1.  **Install the SSH MCP Server**

    Navigate to your project directory and install the server globally using `uv`:

    ```bash
    cd /path/to/ssh_mcp_server
    uv tool install .
    ```

    This makes the `ssh-mcp-server` command available globally on your system.

2.  **Configure Your MCP Client**

    Add the server configuration to your MCP client's `server.json` file.

    **For Claude Desktop**, the `server.json` file is typically located at:
    *   **macOS**: `~/Library/Application Support/Claude/server.json`
    *   **Windows**: `%APPDATA%\Claude\server.json`
    *   **Linux**: `~/.config/Claude/server.json`

    Add the following configuration:

    ```json
    {
      "mcpServers": {
        "ssh": {
          "command": "uvx",
          "args": ["ssh-mcp-server"]
        }
      }
    }
    ```

3.  **Restart Your MCP Client**

    After updating the configuration, restart your MCP client to load the new server.

### Development Installation

For those contributing to or modifying the SSH MCP Server:

1.  **Clone and Set Up the Environment**

    ```bash
    git clone <repository-url>
    cd ssh_mcp_server
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    pip install -e ".[dev]"
    ```

2.  **Install the Tool for Development**

    ```bash
    uv tool install .
    ```

3.  **Update After Changes**

    Whenever you modify the code, reinstall the tool to apply your changes:

    ```bash
    uv tool install .
    ```

### Verification

To verify the installation was successful:

1.  **Check if the command is available:**
    ```bash
    uvx ssh-mcp-server --help
    ```
2.  Check your MCP client's logs for a successful server connection.
3.  Test the SSH functionality through your MCP client.

### Troubleshooting

**Command Not Found**

If `uvx ssh-mcp-server` returns a "command not found" error:
*   Ensure you ran `uv tool install .` from the project's root directory.
*   Verify that `uv` is installed correctly and its bin directory is in your system's `PATH`.

**Server Connection Issues**

If your MCP client fails to connect to the server:
*   Double-check that the `server.json` configuration is correct and contains no typos.
*   Confirm the `server.json` file is in the correct location for your client and OS.
*   Restart your MCP client after making any configuration changes.

**Permission Issues**

If you encounter permission errors during SSH operations:
*   Ensure your SSH keys are set up correctly for the target servers.
*   Verify you have network connectivity to the target hosts and are not blocked by a firewall.