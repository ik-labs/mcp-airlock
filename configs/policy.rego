package airlock.authz

import rego.v1

# Default deny
default allow := false

# Allow health checks without authentication
allow if {
    input.path in ["/live", "/ready", "/info", "/metrics"]
}

# Demo users with different roles
demo_users := {
    "admin-user": {
        "role": "admin",
        "groups": ["admins", "developers"],
        "clearance": "high"
    },
    "dev-user": {
        "role": "developer", 
        "groups": ["developers"],
        "clearance": "medium"
    },
    "readonly-user": {
        "role": "viewer",
        "groups": ["viewers"],
        "clearance": "low"
    }
}

# Extract user from JWT token (simplified for demo)
user := demo_users[input.token.sub] if {
    input.token.sub in demo_users
}

# Admin users can do anything
allow if {
    user.role == "admin"
}

# Developers can read docs and query analytics
allow if {
    user.role == "developer"
    input.method == "GET"
    startswith(input.path, "/mcp")
}

allow if {
    user.role == "developer"
    input.tool_name in ["search_docs", "read_file", "query_metrics"]
}

# Viewers can only search docs (read-only)
allow if {
    user.role == "viewer"
    input.tool_name in ["search_docs"]
}

# Block access to sensitive files for non-admin users
deny if {
    user.role != "admin"
    input.tool_name == "read_file"
    contains(input.tool_args.file_path, "secret")
}

deny if {
    user.role != "admin"
    input.tool_name == "read_file"
    contains(input.tool_args.file_path, "config")
}

# Rate limiting based on user role
rate_limit := 1000 if user.role == "admin"
rate_limit := 100 if user.role == "developer"  
rate_limit := 50 if user.role == "viewer"

# Audit requirements
audit_required := true if {
    input.tool_name in ["export_data", "generate_report"]
}

audit_required := true if {
    user.clearance == "high"
}

# Virtual root access control
virtual_root_allowed := true if {
    user.role == "admin"
}

virtual_root_allowed := true if {
    user.role == "developer"
    input.virtual_root in ["mcp://docs/", "mcp://temp/"]
}

virtual_root_allowed := true if {
    user.role == "viewer"
    input.virtual_root == "mcp://docs/"
    input.operation == "read"
}