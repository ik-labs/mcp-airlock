# Integration Examples

This directory contains practical examples for integrating with MCP Airlock.

## Available Examples

- [TypeScript/Node.js Client](typescript-client.md) - Complete TypeScript client implementation
- [Python Client](python-client.md) - Python client with async support
- [Go Client](go-client.md) - Go client implementation
- [cURL Examples](curl-examples.md) - Command-line testing and debugging
- [Authentication Flows](auth-flows.md) - Different authentication patterns
- [Error Handling](error-handling.md) - Robust error handling patterns

## Quick Examples

### Basic Connection (TypeScript)

```typescript
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';

const client = new Client(
  { name: "my-app", version: "1.0.0" },
  { capabilities: { tools: {}, resources: {} } }
);

const transport = new SSEClientTransport(
  new URL('https://airlock.example.com/mcp/v1/sse'),
  { headers: { 'Authorization': `Bearer ${token}` } }
);

await client.connect(transport);
const tools = await client.listTools();
console.log('Available tools:', tools);
```

### Basic Connection (Python)

```python
import asyncio
import aiohttp
from mcp import ClientSession, StdioServerParameters

async def main():
    session = ClientSession()
    
    # Configure with authentication
    session.headers['Authorization'] = f'Bearer {token}'
    
    async with session.connect('https://airlock.example.com/mcp/v1/sse') as client:
        tools = await client.list_tools()
        print(f'Available tools: {tools}')
        
        result = await client.call_tool('read_file', {
            'path': 'mcp://repo/README.md'
        })
        print(f'File content: {result}')

asyncio.run(main())
```

### Basic Connection (cURL)

```bash
# Get JWT token
TOKEN=$(curl -s -X POST https://auth.example.com/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET" \
  | jq -r .access_token)

# Initialize MCP session
curl -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"curl-client","version":"1.0.0"}}}' \
     https://airlock.example.com/mcp/v1/initialize

# List available tools
curl -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
     https://airlock.example.com/mcp/v1/tools/list
```

## Common Patterns

### Connection Management

```typescript
class AirlockConnection {
  private client: Client;
  private transport: SSEClientTransport;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;

  async connect(endpoint: string, token: string) {
    this.transport = new SSEClientTransport(
      new URL(endpoint),
      { headers: { 'Authorization': `Bearer ${token}` } }
    );

    this.transport.onclose = () => this.handleDisconnect();
    this.transport.onerror = (error) => this.handleError(error);

    await this.client.connect(this.transport);
    this.reconnectAttempts = 0; // Reset on successful connection
  }

  private async handleDisconnect() {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
      
      console.log(`Reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);
      setTimeout(() => this.reconnect(), delay);
    } else {
      console.error('Max reconnection attempts reached');
    }
  }
}
```

### Error Handling

```typescript
async function callToolWithRetry(
  client: Client, 
  toolName: string, 
  args: any, 
  maxRetries = 3
) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await client.callTool({ name: toolName, arguments: args });
    } catch (error) {
      if (error.code === 'TooManyRequests' && attempt < maxRetries) {
        const retryAfter = error.data?.retry_after || Math.pow(2, attempt);
        console.log(`Rate limited, retrying in ${retryAfter}s`);
        await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
        continue;
      }
      
      if (error.code === 'InvalidRequest' && error.data?.reason === 'invalid_token') {
        console.log('Token expired, refreshing...');
        await this.refreshToken();
        continue;
      }
      
      throw error;
    }
  }
}
```

### Batch Operations

```typescript
async function batchReadFiles(client: Client, paths: string[]) {
  const results = await Promise.allSettled(
    paths.map(path => 
      client.callTool({
        name: 'read_file',
        arguments: { path }
      })
    )
  );

  return results.map((result, index) => ({
    path: paths[index],
    success: result.status === 'fulfilled',
    data: result.status === 'fulfilled' ? result.value : null,
    error: result.status === 'rejected' ? result.reason : null
  }));
}
```

## Testing Examples

### Unit Testing

```typescript
import { jest } from '@jest/globals';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';

describe('AirlockClient', () => {
  let mockTransport: jest.Mocked<SSEClientTransport>;
  let client: Client;

  beforeEach(() => {
    mockTransport = {
      connect: jest.fn(),
      close: jest.fn(),
      send: jest.fn(),
      onmessage: jest.fn(),
      onclose: jest.fn(),
      onerror: jest.fn()
    } as any;

    client = new Client(
      { name: 'test-client', version: '1.0.0' },
      { capabilities: {} }
    );
  });

  test('should handle authentication errors', async () => {
    mockTransport.send.mockRejectedValue({
      code: 'InvalidRequest',
      message: 'Authentication failed',
      data: { reason: 'invalid_token' }
    });

    await expect(
      client.callTool({ name: 'read_file', arguments: { path: 'test.txt' } })
    ).rejects.toMatchObject({
      code: 'InvalidRequest',
      data: { reason: 'invalid_token' }
    });
  });

  test('should retry on rate limiting', async () => {
    mockTransport.send
      .mockRejectedValueOnce({
        code: 'TooManyRequests',
        data: { retry_after: 1 }
      })
      .mockResolvedValueOnce({
        content: [{ type: 'text', text: 'file content' }]
      });

    const result = await callToolWithRetry(
      client, 
      'read_file', 
      { path: 'test.txt' }
    );

    expect(result.content[0].text).toBe('file content');
    expect(mockTransport.send).toHaveBeenCalledTimes(2);
  });
});
```

### Integration Testing

```typescript
describe('Airlock Integration', () => {
  let client: Client;
  let transport: SSEClientTransport;

  beforeAll(async () => {
    // Use test environment
    const endpoint = process.env.AIRLOCK_TEST_ENDPOINT || 'http://localhost:8080/mcp/v1/sse';
    const token = process.env.AIRLOCK_TEST_TOKEN;

    transport = new SSEClientTransport(
      new URL(endpoint),
      { headers: { 'Authorization': `Bearer ${token}` } }
    );

    client = new Client(
      { name: 'integration-test', version: '1.0.0' },
      { capabilities: { tools: {}, resources: {} } }
    );

    await client.connect(transport);
  });

  afterAll(async () => {
    await transport.close();
  });

  test('should list available tools', async () => {
    const result = await client.listTools();
    expect(result.tools).toBeInstanceOf(Array);
    expect(result.tools.length).toBeGreaterThan(0);
  });

  test('should read file with redaction', async () => {
    const result = await client.callTool({
      name: 'read_file',
      arguments: { path: 'mcp://repo/test-file-with-email.txt' }
    });

    expect(result.content[0].text).toContain('[redacted-email]');
    expect(result.content[0].text).not.toMatch(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/);
  });

  test('should respect policy restrictions', async () => {
    await expect(
      client.callTool({
        name: 'read_file',
        arguments: { path: '/etc/passwd' }
      })
    ).rejects.toMatchObject({
      code: 'Forbidden',
      data: { reason: expect.stringContaining('not allowed') }
    });
  });
});
```

## Performance Examples

### Load Testing

```typescript
import { performance } from 'perf_hooks';

async function loadTest(
  endpoint: string, 
  token: string, 
  concurrency: number, 
  duration: number
) {
  const clients: Client[] = [];
  const results: number[] = [];
  
  // Create multiple clients
  for (let i = 0; i < concurrency; i++) {
    const transport = new SSEClientTransport(
      new URL(endpoint),
      { headers: { 'Authorization': `Bearer ${token}` } }
    );
    
    const client = new Client(
      { name: `load-test-${i}`, version: '1.0.0' },
      { capabilities: {} }
    );
    
    await client.connect(transport);
    clients.push(client);
  }

  const startTime = performance.now();
  const endTime = startTime + duration * 1000;

  // Run concurrent requests
  const promises = clients.map(async (client, index) => {
    let requestCount = 0;
    
    while (performance.now() < endTime) {
      const requestStart = performance.now();
      
      try {
        await client.callTool({
          name: 'read_file',
          arguments: { path: 'mcp://repo/small-file.txt' }
        });
        
        const requestTime = performance.now() - requestStart;
        results.push(requestTime);
        requestCount++;
      } catch (error) {
        console.error(`Client ${index} error:`, error);
      }
    }
    
    return requestCount;
  });

  const requestCounts = await Promise.all(promises);
  
  // Calculate statistics
  const totalRequests = requestCounts.reduce((sum, count) => sum + count, 0);
  const actualDuration = (performance.now() - startTime) / 1000;
  const rps = totalRequests / actualDuration;
  
  results.sort((a, b) => a - b);
  const p50 = results[Math.floor(results.length * 0.5)];
  const p95 = results[Math.floor(results.length * 0.95)];
  const p99 = results[Math.floor(results.length * 0.99)];

  console.log(`Load Test Results:`);
  console.log(`  Duration: ${actualDuration.toFixed(2)}s`);
  console.log(`  Total Requests: ${totalRequests}`);
  console.log(`  Requests/sec: ${rps.toFixed(2)}`);
  console.log(`  Latency p50: ${p50.toFixed(2)}ms`);
  console.log(`  Latency p95: ${p95.toFixed(2)}ms`);
  console.log(`  Latency p99: ${p99.toFixed(2)}ms`);

  // Cleanup
  await Promise.all(clients.map(client => client.close()));
}

// Run load test
loadTest('https://airlock.example.com/mcp/v1/sse', token, 10, 60);
```

These examples provide practical starting points for integrating with MCP Airlock across different programming languages and use cases.