#!/usr/bin/env python3
"""
Generate demo JWT tokens for Airlock hackathon demo.
These tokens are for demonstration purposes only.
"""

import jwt
import json
from datetime import datetime, timedelta

# Demo secret (DO NOT use in production)
SECRET = "demo-secret-key-for-hackathon-only"

def generate_token(user_id, role, groups, expires_hours=24):
    """Generate a JWT token for demo purposes."""
    payload = {
        "sub": user_id,
        "role": role,
        "groups": groups,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=expires_hours),
        "iss": "airlock-demo",
        "aud": "mcp-airlock"
    }
    
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    return token

def main():
    """Generate demo tokens for different user types."""
    
    tokens = {
        "admin": generate_token("admin-user", "admin", ["admins", "developers"]),
        "developer": generate_token("dev-user", "developer", ["developers"]),
        "viewer": generate_token("readonly-user", "viewer", ["viewers"])
    }
    
    print("=== MCP Airlock Demo Tokens ===\n")
    
    for role, token in tokens.items():
        print(f"{role.upper()} TOKEN:")
        print(f"User: {role}-user")
        print(f"Token: {token}")
        print(f"Curl example:")
        print(f'curl -H "Authorization: Bearer {token}" http://localhost:8080/mcp/tools')
        print()
    
    # Save tokens to file for easy access
    with open("demo-tokens.json", "w") as f:
        json.dump(tokens, f, indent=2)
    
    print("Tokens saved to demo-tokens.json")
    print("\nTo test different access levels:")
    print("1. Use admin token - full access")
    print("2. Use developer token - limited access, can't read secrets")
    print("3. Use viewer token - read-only access to docs")

if __name__ == "__main__":
    main()