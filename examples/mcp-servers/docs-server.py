#!/usr/bin/env python3
"""
Sample MCP Documentation Server

This is a demonstration MCP server that provides document search and retrieval
capabilities. It's designed to work with MCP Airlock for secure access control.
"""

import asyncio
import json
import logging
import os
import socket
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

# Mock MCP SDK imports (replace with actual SDK when available)
class MCPServer:
    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version
        self.tools = {}
        self.resources = {}
        
    def add_tool(self, name: str, description: str, handler):
        self.tools[name] = {
            'name': name,
            'description': description,
            'handler': handler
        }
    
    def add_resource(self, uri: str, name: str, description: str, handler):
        self.resources[uri] = {
            'uri': uri,
            'name': name,
            'description': description,
            'handler': handler
        }

class DocumentationServer:
    """Sample MCP server for document search and retrieval"""
    
    def __init__(self, docs_root: str = "/mnt/docs"):
        self.docs_root = Path(docs_root)
        self.server = MCPServer("docs-server", "1.0.0")
        self.setup_tools()
        self.setup_resources()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def setup_tools(self):
        """Register available tools"""
        self.server.add_tool(
            "search_docs",
            "Search for documents containing specific terms",
            self.search_docs
        )
        
        self.server.add_tool(
            "read_file",
            "Read the contents of a specific file",
            self.read_file
        )
        
        self.server.add_tool(
            "list_directory",
            "List files and directories in a path",
            self.list_directory
        )
    
    def setup_resources(self):
        """Register available resources"""
        self.server.add_resource(
            "mcp://docs/",
            "Documentation Root",
            "Root directory for all documentation",
            self.get_resource
        )
    
    async def search_docs(self, query: str, max_results: int = 10) -> Dict[str, Any]:
        """Search for documents containing the query terms"""
        try:
            results = []
            query_lower = query.lower()
            
            # Simple file search implementation
            for file_path in self.docs_root.rglob("*.md"):
                if not file_path.is_file():
                    continue
                    
                try:
                    content = file_path.read_text(encoding='utf-8')
                    if query_lower in content.lower():
                        # Calculate relevance score (simple word count)
                        score = content.lower().count(query_lower)
                        
                        results.append({
                            "path": str(file_path.relative_to(self.docs_root)),
                            "title": file_path.stem.replace('-', ' ').replace('_', ' ').title(),
                            "score": score,
                            "snippet": self._extract_snippet(content, query, 200)
                        })
                        
                        if len(results) >= max_results:
                            break
                            
                except (UnicodeDecodeError, PermissionError) as e:
                    self.logger.warning(f"Could not read file {file_path}: {e}")
                    continue
            
            # Sort by relevance score
            results.sort(key=lambda x: x['score'], reverse=True)
            
            return {
                "query": query,
                "total_results": len(results),
                "results": results[:max_results]
            }
            
        except Exception as e:
            self.logger.error(f"Error searching docs: {e}")
            return {
                "error": f"Search failed: {str(e)}",
                "query": query,
                "total_results": 0,
                "results": []
            }
    
    async def read_file(self, file_path: str) -> Dict[str, Any]:
        """Read the contents of a specific file"""
        try:
            # Normalize and validate path
            normalized_path = Path(file_path).resolve()
            full_path = self.docs_root / normalized_path.relative_to(normalized_path.anchor)
            
            # Security check: ensure path is within docs root
            if not str(full_path).startswith(str(self.docs_root)):
                return {
                    "error": "Access denied: path outside documentation root",
                    "path": file_path
                }
            
            if not full_path.exists():
                return {
                    "error": "File not found",
                    "path": file_path
                }
            
            if not full_path.is_file():
                return {
                    "error": "Path is not a file",
                    "path": file_path
                }
            
            content = full_path.read_text(encoding='utf-8')
            
            return {
                "path": file_path,
                "size": len(content),
                "content": content,
                "mime_type": self._get_mime_type(full_path)
            }
            
        except Exception as e:
            self.logger.error(f"Error reading file {file_path}: {e}")
            return {
                "error": f"Failed to read file: {str(e)}",
                "path": file_path
            }
    
    async def list_directory(self, dir_path: str = "") -> Dict[str, Any]:
        """List files and directories in a path"""
        try:
            # Normalize path
            if not dir_path:
                target_path = self.docs_root
            else:
                normalized_path = Path(dir_path).resolve()
                target_path = self.docs_root / normalized_path.relative_to(normalized_path.anchor)
            
            # Security check: ensure path is within docs root
            if not str(target_path).startswith(str(self.docs_root)):
                return {
                    "error": "Access denied: path outside documentation root",
                    "path": dir_path
                }
            
            if not target_path.exists():
                return {
                    "error": "Directory not found",
                    "path": dir_path
                }
            
            if not target_path.is_dir():
                return {
                    "error": "Path is not a directory",
                    "path": dir_path
                }
            
            items = []
            for item in sorted(target_path.iterdir()):
                try:
                    stat = item.stat()
                    items.append({
                        "name": item.name,
                        "type": "directory" if item.is_dir() else "file",
                        "size": stat.st_size if item.is_file() else None,
                        "modified": stat.st_mtime,
                        "path": str(item.relative_to(self.docs_root))
                    })
                except (OSError, PermissionError):
                    # Skip items we can't access
                    continue
            
            return {
                "path": dir_path,
                "total_items": len(items),
                "items": items
            }
            
        except Exception as e:
            self.logger.error(f"Error listing directory {dir_path}: {e}")
            return {
                "error": f"Failed to list directory: {str(e)}",
                "path": dir_path
            }
    
    async def get_resource(self, uri: str) -> Dict[str, Any]:
        """Get a resource by URI"""
        try:
            # Parse URI to extract path
            if uri.startswith("mcp://docs/"):
                path = uri[11:]  # Remove "mcp://docs/" prefix
                return await self.read_file(path)
            else:
                return {
                    "error": "Unsupported URI scheme",
                    "uri": uri
                }
                
        except Exception as e:
            self.logger.error(f"Error getting resource {uri}: {e}")
            return {
                "error": f"Failed to get resource: {str(e)}",
                "uri": uri
            }
    
    def _extract_snippet(self, content: str, query: str, max_length: int) -> str:
        """Extract a snippet around the query match"""
        query_lower = query.lower()
        content_lower = content.lower()
        
        # Find the first occurrence
        index = content_lower.find(query_lower)
        if index == -1:
            return content[:max_length] + "..." if len(content) > max_length else content
        
        # Calculate snippet boundaries
        start = max(0, index - max_length // 2)
        end = min(len(content), start + max_length)
        
        snippet = content[start:end]
        
        # Add ellipsis if truncated
        if start > 0:
            snippet = "..." + snippet
        if end < len(content):
            snippet = snippet + "..."
        
        return snippet
    
    def _get_mime_type(self, file_path: Path) -> str:
        """Get MIME type based on file extension"""
        extension = file_path.suffix.lower()
        mime_types = {
            '.md': 'text/markdown',
            '.txt': 'text/plain',
            '.json': 'application/json',
            '.yaml': 'application/yaml',
            '.yml': 'application/yaml',
            '.html': 'text/html',
            '.css': 'text/css',
            '.js': 'application/javascript',
        }
        return mime_types.get(extension, 'application/octet-stream')
    
    async def run_unix_socket(self, socket_path: str):
        """Run the server on a Unix socket"""
        self.logger.info(f"Starting docs server on Unix socket: {socket_path}")
        
        # Remove existing socket file
        if os.path.exists(socket_path):
            os.unlink(socket_path)
        
        # Create socket directory if it doesn't exist
        os.makedirs(os.path.dirname(socket_path), exist_ok=True)
        
        # Simple socket server implementation
        server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_socket.bind(socket_path)
        server_socket.listen(5)
        
        # Set socket permissions
        os.chmod(socket_path, 0o666)
        
        self.logger.info(f"Docs server listening on {socket_path}")
        
        try:
            while True:
                client_socket, _ = server_socket.accept()
                asyncio.create_task(self._handle_client(client_socket))
        except KeyboardInterrupt:
            self.logger.info("Shutting down docs server")
        finally:
            server_socket.close()
            if os.path.exists(socket_path):
                os.unlink(socket_path)
    
    async def _handle_client(self, client_socket):
        """Handle a client connection"""
        try:
            # Read request
            data = client_socket.recv(4096).decode('utf-8')
            if not data:
                return
            
            request = json.loads(data)
            method = request.get('method')
            params = request.get('params', {})
            
            # Route to appropriate handler
            if method == 'search_docs':
                response = await self.search_docs(**params)
            elif method == 'read_file':
                response = await self.read_file(**params)
            elif method == 'list_directory':
                response = await self.list_directory(**params)
            elif method == 'get_resource':
                response = await self.get_resource(**params)
            else:
                response = {"error": f"Unknown method: {method}"}
            
            # Send response
            response_data = json.dumps(response).encode('utf-8')
            client_socket.send(response_data)
            
        except Exception as e:
            self.logger.error(f"Error handling client: {e}")
            error_response = json.dumps({"error": str(e)}).encode('utf-8')
            client_socket.send(error_response)
        finally:
            client_socket.close()

def main():
    """Main entry point"""
    # Configuration from environment
    docs_root = os.getenv('DOCS_ROOT', '/mnt/docs')
    socket_path = os.getenv('MCP_SOCKET_PATH', '/run/mcp/docs.sock')
    
    # Create docs server
    server = DocumentationServer(docs_root)
    
    # Create sample documentation if directory is empty
    docs_path = Path(docs_root)
    if docs_path.exists() and not any(docs_path.iterdir()):
        create_sample_docs(docs_path)
    
    # Run the server
    try:
        asyncio.run(server.run_unix_socket(socket_path))
    except KeyboardInterrupt:
        print("\nShutting down docs server...")
        sys.exit(0)

def create_sample_docs(docs_root: Path):
    """Create sample documentation for testing"""
    sample_docs = {
        "README.md": """# Documentation Server

This is a sample documentation server for MCP Airlock testing.

## Features

- Document search
- File reading
- Directory listing
- Secure path validation

## Usage

Use the MCP tools to interact with this documentation:

- `search_docs`: Search for documents
- `read_file`: Read file contents
- `list_directory`: List directory contents
""",
        "api/README.md": """# API Documentation

## Authentication

All API calls must be authenticated through MCP Airlock.

## Endpoints

### Search Documents
- Tool: `search_docs`
- Parameters: `query`, `max_results`

### Read File
- Tool: `read_file`
- Parameters: `file_path`

### List Directory
- Tool: `list_directory`
- Parameters: `dir_path`
""",
        "guides/getting-started.md": """# Getting Started Guide

## Prerequisites

1. MCP Airlock deployed and configured
2. Proper authentication setup
3. Access to documentation resources

## First Steps

1. Connect to MCP Airlock
2. Authenticate with your credentials
3. Use the search tool to find relevant documentation
4. Read specific files for detailed information

## Security

All access is controlled through MCP Airlock policies.
""",
        "troubleshooting.md": """# Troubleshooting

## Common Issues

### Authentication Failures
- Check your OIDC configuration
- Verify group membership
- Review audit logs

### Permission Denied
- Check policy configuration
- Verify resource paths
- Review virtual root mappings

### Performance Issues
- Monitor resource usage
- Check rate limiting
- Review caching configuration
"""
    }
    
    for file_path, content in sample_docs.items():
        full_path = docs_root / file_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text(content)

if __name__ == "__main__":
    main()