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

### Using pip

```bash
pip install -r requirements.txt
