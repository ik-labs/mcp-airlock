#!/usr/bin/env python3
"""
Sample MCP Analytics Server

This is a demonstration MCP server that provides analytics and metrics
capabilities. It's designed to work with MCP Airlock for secure access control.
"""

import asyncio
import json
import logging
import os
import socket
import sqlite3
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional
import random
import time

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

class AnalyticsServer:
    """Sample MCP server for analytics and metrics"""
    
    def __init__(self, db_path: str = "/var/lib/analytics/analytics.db"):
        self.db_path = Path(db_path)
        self.server = MCPServer("analytics-server", "1.0.0")
        self.setup_database()
        self.setup_tools()
        self.setup_resources()
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Start background data generation
        asyncio.create_task(self._generate_sample_data())
    
    def setup_database(self):
        """Initialize the analytics database"""
        # Create directory if it doesn't exist
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                metric_name TEXT NOT NULL,
                metric_value REAL NOT NULL,
                tags TEXT,
                source TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_type TEXT NOT NULL,
                event_data TEXT,
                user_id TEXT,
                session_id TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                report_name TEXT NOT NULL,
                report_type TEXT NOT NULL,
                report_data TEXT NOT NULL,
                parameters TEXT
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_name ON metrics(metric_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)')
        
        conn.commit()
        conn.close()
    
    def setup_tools(self):
        """Register available tools"""
        self.server.add_tool(
            "query_metrics",
            "Query metrics data with filters and aggregations",
            self.query_metrics
        )
        
        self.server.add_tool(
            "generate_report",
            "Generate analytics reports",
            self.generate_report
        )
        
        self.server.add_tool(
            "export_data",
            "Export analytics data in various formats",
            self.export_data
        )
        
        self.server.add_tool(
            "get_dashboard_data",
            "Get data for analytics dashboards",
            self.get_dashboard_data
        )
    
    def setup_resources(self):
        """Register available resources"""
        self.server.add_resource(
            "mcp://analytics/",
            "Analytics Root",
            "Root resource for analytics data",
            self.get_resource
        )
    
    async def query_metrics(self, 
                          metric_name: Optional[str] = None,
                          start_time: Optional[str] = None,
                          end_time: Optional[str] = None,
                          aggregation: str = "avg",
                          group_by: Optional[str] = None,
                          limit: int = 100) -> Dict[str, Any]:
        """Query metrics data with filters and aggregations"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Build query
            query = "SELECT timestamp, metric_name, metric_value, tags, source FROM metrics WHERE 1=1"
            params = []
            
            if metric_name:
                query += " AND metric_name = ?"
                params.append(metric_name)
            
            if start_time:
                query += " AND timestamp >= ?"
                params.append(start_time)
            
            if end_time:
                query += " AND timestamp <= ?"
                params.append(end_time)
            
            # Add aggregation if specified
            if aggregation in ["avg", "sum", "min", "max", "count"]:
                if group_by == "hour":
                    query = f"""
                        SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as time_bucket,
                               metric_name,
                               {aggregation}(metric_value) as value,
                               COUNT(*) as count
                        FROM metrics 
                        WHERE 1=1
                    """
                    if metric_name:
                        query += " AND metric_name = ?"
                    if start_time:
                        query += " AND timestamp >= ?"
                    if end_time:
                        query += " AND timestamp <= ?"
                    query += " GROUP BY time_bucket, metric_name ORDER BY time_bucket DESC"
                elif group_by == "day":
                    query = f"""
                        SELECT strftime('%Y-%m-%d', timestamp) as time_bucket,
                               metric_name,
                               {aggregation}(metric_value) as value,
                               COUNT(*) as count
                        FROM metrics 
                        WHERE 1=1
                    """
                    if metric_name:
                        query += " AND metric_name = ?"
                    if start_time:
                        query += " AND timestamp >= ?"
                    if end_time:
                        query += " AND timestamp <= ?"
                    query += " GROUP BY time_bucket, metric_name ORDER BY time_bucket DESC"
            
            query += f" LIMIT {limit}"
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            # Format results
            if group_by:
                results = []
                for row in rows:
                    results.append({
                        "time_bucket": row[0],
                        "metric_name": row[1],
                        "value": row[2],
                        "count": row[3] if len(row) > 3 else 1
                    })
            else:
                results = []
                for row in rows:
                    results.append({
                        "timestamp": row[0],
                        "metric_name": row[1],
                        "value": row[2],
                        "tags": json.loads(row[3]) if row[3] else {},
                        "source": row[4]
                    })
            
            conn.close()
            
            return {
                "query_params": {
                    "metric_name": metric_name,
                    "start_time": start_time,
                    "end_time": end_time,
                    "aggregation": aggregation,
                    "group_by": group_by,
                    "limit": limit
                },
                "total_results": len(results),
                "results": results
            }
            
        except Exception as e:
            self.logger.error(f"Error querying metrics: {e}")
            return {
                "error": f"Query failed: {str(e)}",
                "query_params": {
                    "metric_name": metric_name,
                    "start_time": start_time,
                    "end_time": end_time
                },
                "total_results": 0,
                "results": []
            }
    
    async def generate_report(self, 
                            report_type: str,
                            parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate analytics reports"""
        try:
            if parameters is None:
                parameters = {}
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            report_data = {}
            
            if report_type == "summary":
                # Generate summary report
                cursor.execute("""
                    SELECT metric_name, 
                           COUNT(*) as count,
                           AVG(metric_value) as avg_value,
                           MIN(metric_value) as min_value,
                           MAX(metric_value) as max_value
                    FROM metrics 
                    WHERE timestamp >= datetime('now', '-24 hours')
                    GROUP BY metric_name
                """)
                
                metrics_summary = []
                for row in cursor.fetchall():
                    metrics_summary.append({
                        "metric_name": row[0],
                        "count": row[1],
                        "avg_value": round(row[2], 2),
                        "min_value": row[3],
                        "max_value": row[4]
                    })
                
                cursor.execute("""
                    SELECT event_type, COUNT(*) as count
                    FROM events 
                    WHERE timestamp >= datetime('now', '-24 hours')
                    GROUP BY event_type
                """)
                
                events_summary = []
                for row in cursor.fetchall():
                    events_summary.append({
                        "event_type": row[0],
                        "count": row[1]
                    })
                
                report_data = {
                    "period": "Last 24 hours",
                    "metrics_summary": metrics_summary,
                    "events_summary": events_summary,
                    "total_metrics": sum(m["count"] for m in metrics_summary),
                    "total_events": sum(e["count"] for e in events_summary)
                }
            
            elif report_type == "performance":
                # Generate performance report
                cursor.execute("""
                    SELECT strftime('%H:00', timestamp) as hour,
                           AVG(metric_value) as avg_response_time
                    FROM metrics 
                    WHERE metric_name = 'response_time'
                    AND timestamp >= datetime('now', '-24 hours')
                    GROUP BY hour
                    ORDER BY hour
                """)
                
                hourly_performance = []
                for row in cursor.fetchall():
                    hourly_performance.append({
                        "hour": row[0],
                        "avg_response_time": round(row[1], 2)
                    })
                
                cursor.execute("""
                    SELECT AVG(metric_value) as avg_cpu,
                           MAX(metric_value) as max_cpu
                    FROM metrics 
                    WHERE metric_name = 'cpu_usage'
                    AND timestamp >= datetime('now', '-24 hours')
                """)
                
                cpu_stats = cursor.fetchone()
                
                report_data = {
                    "period": "Last 24 hours",
                    "hourly_performance": hourly_performance,
                    "cpu_stats": {
                        "avg_cpu": round(cpu_stats[0] or 0, 2),
                        "max_cpu": round(cpu_stats[1] or 0, 2)
                    }
                }
            
            elif report_type == "usage":
                # Generate usage report
                cursor.execute("""
                    SELECT user_id, COUNT(*) as event_count
                    FROM events 
                    WHERE timestamp >= datetime('now', '-7 days')
                    AND user_id IS NOT NULL
                    GROUP BY user_id
                    ORDER BY event_count DESC
                    LIMIT 10
                """)
                
                top_users = []
                for row in cursor.fetchall():
                    top_users.append({
                        "user_id": row[0],
                        "event_count": row[1]
                    })
                
                cursor.execute("""
                    SELECT strftime('%Y-%m-%d', timestamp) as date,
                           COUNT(DISTINCT user_id) as unique_users,
                           COUNT(*) as total_events
                    FROM events 
                    WHERE timestamp >= datetime('now', '-7 days')
                    GROUP BY date
                    ORDER BY date
                """)
                
                daily_usage = []
                for row in cursor.fetchall():
                    daily_usage.append({
                        "date": row[0],
                        "unique_users": row[1],
                        "total_events": row[2]
                    })
                
                report_data = {
                    "period": "Last 7 days",
                    "top_users": top_users,
                    "daily_usage": daily_usage
                }
            
            else:
                return {
                    "error": f"Unknown report type: {report_type}",
                    "available_types": ["summary", "performance", "usage"]
                }
            
            # Save report to database
            report_name = f"{report_type}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            cursor.execute("""
                INSERT INTO reports (report_name, report_type, report_data, parameters)
                VALUES (?, ?, ?, ?)
            """, (report_name, report_type, json.dumps(report_data), json.dumps(parameters)))
            
            conn.commit()
            conn.close()
            
            return {
                "report_name": report_name,
                "report_type": report_type,
                "generated_at": datetime.now().isoformat(),
                "parameters": parameters,
                "data": report_data
            }
            
        except Exception as e:
            self.logger.error(f"Error generating report: {e}")
            return {
                "error": f"Report generation failed: {str(e)}",
                "report_type": report_type
            }
    
    async def export_data(self, 
                         export_format: str = "json",
                         data_type: str = "metrics",
                         start_time: Optional[str] = None,
                         end_time: Optional[str] = None,
                         limit: int = 1000) -> Dict[str, Any]:
        """Export analytics data in various formats"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Build query based on data type
            if data_type == "metrics":
                query = "SELECT * FROM metrics WHERE 1=1"
                params = []
                
                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)
                
                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)
                
                query += f" ORDER BY timestamp DESC LIMIT {limit}"
                
            elif data_type == "events":
                query = "SELECT * FROM events WHERE 1=1"
                params = []
                
                if start_time:
                    query += " AND timestamp >= ?"
                    params.append(start_time)
                
                if end_time:
                    query += " AND timestamp <= ?"
                    params.append(end_time)
                
                query += f" ORDER BY timestamp DESC LIMIT {limit}"
                
            else:
                return {
                    "error": f"Unknown data type: {data_type}",
                    "available_types": ["metrics", "events"]
                }
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            # Get column names
            column_names = [description[0] for description in cursor.description]
            
            # Format data
            data = []
            for row in rows:
                record = dict(zip(column_names, row))
                data.append(record)
            
            conn.close()
            
            # Format output based on export format
            if export_format == "json":
                export_data = {
                    "metadata": {
                        "data_type": data_type,
                        "export_format": export_format,
                        "exported_at": datetime.now().isoformat(),
                        "record_count": len(data),
                        "columns": column_names
                    },
                    "data": data
                }
            elif export_format == "csv":
                # Convert to CSV format
                csv_lines = [",".join(column_names)]
                for record in data:
                    csv_line = ",".join(str(record.get(col, "")) for col in column_names)
                    csv_lines.append(csv_line)
                
                export_data = {
                    "metadata": {
                        "data_type": data_type,
                        "export_format": export_format,
                        "exported_at": datetime.now().isoformat(),
                        "record_count": len(data)
                    },
                    "data": "\n".join(csv_lines)
                }
            else:
                return {
                    "error": f"Unsupported export format: {export_format}",
                    "available_formats": ["json", "csv"]
                }
            
            return export_data
            
        except Exception as e:
            self.logger.error(f"Error exporting data: {e}")
            return {
                "error": f"Export failed: {str(e)}",
                "data_type": data_type,
                "export_format": export_format
            }
    
    async def get_dashboard_data(self, dashboard_type: str = "overview") -> Dict[str, Any]:
        """Get data for analytics dashboards"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if dashboard_type == "overview":
                # Get overview dashboard data
                
                # Recent metrics
                cursor.execute("""
                    SELECT metric_name, metric_value, timestamp
                    FROM metrics 
                    WHERE timestamp >= datetime('now', '-1 hour')
                    ORDER BY timestamp DESC
                    LIMIT 20
                """)
                recent_metrics = []
                for row in cursor.fetchall():
                    recent_metrics.append({
                        "metric_name": row[0],
                        "value": row[1],
                        "timestamp": row[2]
                    })
                
                # System health indicators
                cursor.execute("""
                    SELECT AVG(metric_value) as avg_cpu
                    FROM metrics 
                    WHERE metric_name = 'cpu_usage'
                    AND timestamp >= datetime('now', '-5 minutes')
                """)
                avg_cpu = cursor.fetchone()[0] or 0
                
                cursor.execute("""
                    SELECT AVG(metric_value) as avg_memory
                    FROM metrics 
                    WHERE metric_name = 'memory_usage'
                    AND timestamp >= datetime('now', '-5 minutes')
                """)
                avg_memory = cursor.fetchone()[0] or 0
                
                cursor.execute("""
                    SELECT AVG(metric_value) as avg_response_time
                    FROM metrics 
                    WHERE metric_name = 'response_time'
                    AND timestamp >= datetime('now', '-5 minutes')
                """)
                avg_response_time = cursor.fetchone()[0] or 0
                
                dashboard_data = {
                    "dashboard_type": dashboard_type,
                    "last_updated": datetime.now().isoformat(),
                    "recent_metrics": recent_metrics,
                    "health_indicators": {
                        "cpu_usage": round(avg_cpu, 2),
                        "memory_usage": round(avg_memory, 2),
                        "avg_response_time": round(avg_response_time, 2)
                    },
                    "status": "healthy" if avg_cpu < 80 and avg_memory < 80 and avg_response_time < 1000 else "warning"
                }
            
            else:
                return {
                    "error": f"Unknown dashboard type: {dashboard_type}",
                    "available_types": ["overview"]
                }
            
            conn.close()
            return dashboard_data
            
        except Exception as e:
            self.logger.error(f"Error getting dashboard data: {e}")
            return {
                "error": f"Dashboard data retrieval failed: {str(e)}",
                "dashboard_type": dashboard_type
            }
    
    async def get_resource(self, uri: str) -> Dict[str, Any]:
        """Get a resource by URI"""
        try:
            if uri.startswith("mcp://analytics/"):
                resource_path = uri[16:]  # Remove "mcp://analytics/" prefix
                
                if resource_path == "dashboard":
                    return await self.get_dashboard_data()
                elif resource_path.startswith("reports/"):
                    report_name = resource_path[8:]  # Remove "reports/" prefix
                    return await self._get_report(report_name)
                else:
                    return {
                        "error": "Unknown analytics resource",
                        "uri": uri,
                        "available_resources": ["dashboard", "reports/{report_name}"]
                    }
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
    
    async def _get_report(self, report_name: str) -> Dict[str, Any]:
        """Get a specific report by name"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT report_name, report_type, report_data, parameters, created_at
                FROM reports 
                WHERE report_name = ?
            """, (report_name,))
            
            row = cursor.fetchone()
            if not row:
                return {
                    "error": f"Report not found: {report_name}"
                }
            
            conn.close()
            
            return {
                "report_name": row[0],
                "report_type": row[1],
                "data": json.loads(row[2]),
                "parameters": json.loads(row[3]) if row[3] else {},
                "created_at": row[4]
            }
            
        except Exception as e:
            self.logger.error(f"Error getting report {report_name}: {e}")
            return {
                "error": f"Failed to get report: {str(e)}",
                "report_name": report_name
            }
    
    async def _generate_sample_data(self):
        """Generate sample data for testing"""
        while True:
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Generate sample metrics
                metrics = [
                    ("cpu_usage", random.uniform(10, 90)),
                    ("memory_usage", random.uniform(20, 80)),
                    ("response_time", random.uniform(50, 500)),
                    ("request_count", random.randint(1, 100)),
                    ("error_rate", random.uniform(0, 5))
                ]
                
                for metric_name, value in metrics:
                    cursor.execute("""
                        INSERT INTO metrics (metric_name, metric_value, tags, source)
                        VALUES (?, ?, ?, ?)
                    """, (metric_name, value, json.dumps({"environment": "demo"}), "sample_generator"))
                
                # Generate sample events
                event_types = ["user_login", "api_call", "error", "warning", "info"]
                event_type = random.choice(event_types)
                
                cursor.execute("""
                    INSERT INTO events (event_type, event_data, user_id, session_id)
                    VALUES (?, ?, ?, ?)
                """, (event_type, json.dumps({"sample": True}), f"user_{random.randint(1, 10)}", f"session_{random.randint(1, 100)}"))
                
                conn.commit()
                conn.close()
                
                # Wait before generating more data
                await asyncio.sleep(30)  # Generate data every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error generating sample data: {e}")
                await asyncio.sleep(60)  # Wait longer on error
    
    async def run_unix_socket(self, socket_path: str):
        """Run the server on a Unix socket"""
        self.logger.info(f"Starting analytics server on Unix socket: {socket_path}")
        
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
        
        self.logger.info(f"Analytics server listening on {socket_path}")
        
        try:
            while True:
                client_socket, _ = server_socket.accept()
                asyncio.create_task(self._handle_client(client_socket))
        except KeyboardInterrupt:
            self.logger.info("Shutting down analytics server")
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
            if method == 'query_metrics':
                response = await self.query_metrics(**params)
            elif method == 'generate_report':
                response = await self.generate_report(**params)
            elif method == 'export_data':
                response = await self.export_data(**params)
            elif method == 'get_dashboard_data':
                response = await self.get_dashboard_data(**params)
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
    db_path = os.getenv('ANALYTICS_DB_PATH', '/var/lib/analytics/analytics.db')
    socket_path = os.getenv('MCP_SOCKET_PATH', '/run/mcp/analytics.sock')
    
    # Create analytics server
    server = AnalyticsServer(db_path)
    
    # Run the server
    try:
        asyncio.run(server.run_unix_socket(socket_path))
    except KeyboardInterrupt:
        print("\nShutting down analytics server...")
        sys.exit(0)

if __name__ == "__main__":
    main()