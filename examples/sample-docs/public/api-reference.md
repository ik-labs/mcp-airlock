# API Reference

## Authentication

All API requests require a valid JWT token in the Authorization header:

```
Authorization: Bearer <your-token>
```

## Endpoints

### GET /mcp/tools
List available tools

### POST /mcp/tools/call
Execute a tool

Example:
```json
{
  "name": "search_docs",
  "arguments": {
    "query": "authentication"
  }
}
```

## Rate Limits

- Admin users: 1000 requests/minute
- Developer users: 100 requests/minute  
- Viewer users: 50 requests/minute

## Support

Contact: support@example.com
Emergency: (555) 911-HELP