# test_mcp_protocol.py
import asyncio
import json
import subprocess
import sys

async def test_mcp_server():
    # Start your server as a subprocess
    cmd = [
        "/gorgon/ia/pyIAdev/bin/python",  # Use your actual path
        "-m", "ssh_mcp_server.server"
    ]
    
    print(f"Starting server with command: {' '.join(cmd)}")
    
    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd="/gorgon/ia/ssh_mcp_server"  # Use your actual path
    )
    
    # Send initialization request
    init_request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "test-client",
                "version": "1.0.0"
            }
        }
    }
    
    print("Sending initialization request...")
    process.stdin.write(json.dumps(init_request) + "\n")
    process.stdin.flush()
    
    # Wait for response
    try:
        response = process.stdout.readline()
        print(f"Response: {response}")
        
        if response:
            # Send list_tools request
            tools_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            }
            
            print("Sending tools/list request...")
            process.stdin.write(json.dumps(tools_request) + "\n")
            process.stdin.flush()
            
            tools_response = process.stdout.readline()
            print(f"Tools response: {tools_response}")
        
    except Exception as e:
        print(f"Error: {e}")
    
    # Check for errors
    stderr_output = process.stderr.read()
    if stderr_output:
        print(f"Server stderr: {stderr_output}")
    
    process.terminate()

if __name__ == "__main__":
    asyncio.run(test_mcp_server())
