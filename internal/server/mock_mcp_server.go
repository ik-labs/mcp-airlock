package server

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"go.uber.org/zap"
)

// MockMCPServerProcess represents a mock MCP server that can be used for testing
type MockMCPServerProcess struct {
	logger    *zap.Logger
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    io.ReadCloser
	stderr    io.ReadCloser
	responses map[string]interface{}
	mu        sync.RWMutex
	running   bool
}

// NewMockMCPServerProcess creates a new mock MCP server process
func NewMockMCPServerProcess(logger *zap.Logger) *MockMCPServerProcess {
	return &MockMCPServerProcess{
		logger:    logger,
		responses: make(map[string]interface{}),
	}
}

// Start starts the mock MCP server process
func (m *MockMCPServerProcess) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("mock server already running")
	}

	// Create a simple Python script that acts as an MCP server
	script := `#!/usr/bin/env python3
import json
import sys
import time

def handle_request(request):
    method = request.get("method", "")
    request_id = request.get("id")
    
    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [
                    {
                        "name": "mock_tool",
                        "description": "A mock tool for testing",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "query": {
                                    "type": "string",
                                    "description": "Test query"
                                }
                            }
                        }
                    }
                ]
            }
        }
    elif method == "tools/call":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "Mock tool executed successfully"
                    }
                ]
            }
        }
    elif method == "resources/list":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "resources": [
                    {
                        "uri": "mock://resource/1",
                        "name": "Mock Resource",
                        "description": "A mock resource for testing",
                        "mimeType": "text/plain"
                    }
                ]
            }
        }
    elif method == "resources/read":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "contents": [
                    {
                        "uri": "mock://resource/1",
                        "mimeType": "text/plain",
                        "text": "Mock resource content"
                    }
                ]
            }
        }
    elif method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {}
        }
    else:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32601,
                "message": f"Method not found: {method}"
            }
        }

def main():
    # Send initialization message
    init_response = {
        "jsonrpc": "2.0",
        "id": "init",
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": True},
                "resources": {"subscribe": True, "listChanged": True}
            },
            "serverInfo": {
                "name": "mock-mcp-server",
                "version": "1.0.0"
            }
        }
    }
    
    print(json.dumps(init_response), flush=True)
    
    # Process requests
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
            
        try:
            request = json.loads(line)
            response = handle_request(request)
            print(json.dumps(response), flush=True)
        except json.JSONDecodeError:
            error_response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32700,
                    "message": "Parse error"
                }
            }
            print(json.dumps(error_response), flush=True)
        except Exception as e:
            error_response = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {
                    "code": -32000,
                    "message": f"Internal error: {str(e)}"
                }
            }
            print(json.dumps(error_response), flush=True)

if __name__ == "__main__":
    main()
`

	// Write the script to a temporary file
	tmpFile, err := os.CreateTemp("", "mock_mcp_server_*.py")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(script); err != nil {
		return fmt.Errorf("failed to write script: %w", err)
	}

	if err := tmpFile.Chmod(0755); err != nil {
		return fmt.Errorf("failed to make script executable: %w", err)
	}

	// Start the Python process
	m.cmd = exec.CommandContext(ctx, "python3", tmpFile.Name())

	stdin, err := m.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	m.stdin = stdin

	stdout, err := m.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	m.stdout = stdout

	stderr, err := m.cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}
	m.stderr = stderr

	if err := m.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start mock server: %w", err)
	}

	m.running = true
	m.logger.Info("Mock MCP server started", zap.Int("pid", m.cmd.Process.Pid))

	// Start goroutine to handle stderr
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := m.stderr.Read(buf)
			if err != nil {
				return
			}
			if n > 0 {
				m.logger.Debug("Mock server stderr", zap.String("output", string(buf[:n])))
			}
		}
	}()

	return nil
}

// Stop stops the mock MCP server process
func (m *MockMCPServerProcess) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return nil
	}

	m.running = false

	// Close pipes
	if m.stdin != nil {
		m.stdin.Close()
	}
	if m.stdout != nil {
		m.stdout.Close()
	}
	if m.stderr != nil {
		m.stderr.Close()
	}

	// Kill the process
	if m.cmd != nil && m.cmd.Process != nil {
		if err := m.cmd.Process.Kill(); err != nil {
			m.logger.Warn("Failed to kill mock server process", zap.Error(err))
		}

		// Wait for process to exit
		m.cmd.Wait()
	}

	m.logger.Info("Mock MCP server stopped")
	return nil
}

// IsRunning returns whether the mock server is running
func (m *MockMCPServerProcess) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// GetCommand returns the command that can be used to connect to this mock server
func (m *MockMCPServerProcess) GetCommand() []string {
	if m.cmd == nil {
		return nil
	}
	return m.cmd.Args
}

// CreateTestUpstreamConfig creates an upstream config for testing with a real mock MCP server
func CreateTestUpstreamConfig(logger *zap.Logger) (*UpstreamConfig, *MockMCPServerProcess, error) {
	mockServer := NewMockMCPServerProcess(logger)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := mockServer.Start(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to start mock server: %w", err)
	}

	// Wait a bit for the server to initialize
	time.Sleep(100 * time.Millisecond)

	config := &UpstreamConfig{
		Name:    "mock-server",
		Type:    "stdio",
		Command: mockServer.GetCommand(),
		Timeout: 10 * time.Second,
	}

	return config, mockServer, nil
}

// TestWithMockMCPServer is a helper function for tests that need a real MCP server
func TestWithMockMCPServer(t interface{}, testFunc func(*UpstreamConfig, *MockMCPServerProcess)) {
	// This is a helper that can be used in tests
	// The actual implementation would depend on the testing framework being used
}
