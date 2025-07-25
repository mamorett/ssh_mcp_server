#!/bin/bash
set -e

# Activate virtual environment
source /gorgon/ia/pyIAdev/bin/activate

# Set Python path
export PYTHONPATH="/gorgon/ia/ssh_mcp_server/src:$PYTHONPATH"

# Change to project directory
cd /gorgon/ia/ssh_mcp_server

# Run the server
exec python -m ssh_mcp_server.server

