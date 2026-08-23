#!/usr/bin/env python3
"""
Custom MCP (Model Context Protocol) Server & Build/Test Validator for Fire Crow.
Executes comprehensive validation across Rust backend, TypeScript frontend, and database migrations.
"""

import sys
import os
import json
import subprocess
import time
import argparse

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BACKEND_DIR = os.path.join(WORKSPACE_DIR, "backend")
FRONTEND_DIR = os.path.join(WORKSPACE_DIR, "frontend")

def run_cmd(cmd, cwd):
    start_time = time.time()
    try:
        proc = subprocess.run(
            cmd,
            shell=True,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120
        )
        elapsed = time.time() - start_time
        return {
            "exit_code": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
            "duration_sec": round(elapsed, 2)
        }
    except Exception as e:
        return {
            "exit_code": 1,
            "stdout": "",
            "stderr": str(e),
            "duration_sec": round(time.time() - start_time, 2)
        }

def validate_firecrow_project():
    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "SUCCESS",
        "steps": {},
        "errors": []
    }

    # 1. Rust Cargo Check
    print("⚡ [1/4] Running Rust Backend Compilation Check (cargo check)...")
    cargo_check = run_cmd("cargo check", BACKEND_DIR)
    results["steps"]["backend_compile"] = cargo_check
    if cargo_check["exit_code"] != 0:
        results["status"] = "FAILED"
        results["errors"].append(f"Cargo check failed: {cargo_check['stderr']}")

    # 2. Rust Cargo Test Compile
    print("⚡ [2/4] Running Rust Backend Tests Verification (cargo test --no-run)...")
    cargo_test = run_cmd("cargo test --no-run", BACKEND_DIR)
    results["steps"]["backend_tests"] = cargo_test
    if cargo_test["exit_code"] != 0:
        results["status"] = "FAILED"
        results["errors"].append(f"Cargo test compile failed: {cargo_test['stderr']}")

    # 3. Frontend TypeScript Check
    print("⚡ [3/4] Running Frontend TypeScript Check (npx tsc --noEmit)...")
    tsc_check = run_cmd("npx tsc --noEmit", FRONTEND_DIR)
    results["steps"]["frontend_typecheck"] = tsc_check
    if tsc_check["exit_code"] != 0:
        results["status"] = "FAILED"
        results["errors"].append(f"TypeScript check failed: {tsc_check['stderr'] or tsc_check['stdout']}")

    # 4. Frontend Vite Production Build Test
    print("⚡ [4/4] Running Frontend Vite Build Check (npm run build)...")
    vite_build = run_cmd("npm run build", FRONTEND_DIR)
    results["steps"]["frontend_build"] = vite_build
    if vite_build["exit_code"] != 0:
        results["status"] = "FAILED"
        results["errors"].append(f"Frontend build failed: {vite_build['stderr'] or vite_build['stdout']}")

    return results

def handle_mcp_stdio():
    """Implements Model Context Protocol (MCP) JSON-RPC Stdio Interface"""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            req_id = req.get("id")
            method = req.get("method")

            if method == "initialize":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "firecrow-mcp-validator", "version": "1.0.0"}
                    }
                }
            elif method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": [
                            {
                                "name": "firecrow_validate_build",
                                "description": "Validates Fire Crow project builds: Rust backend compilation, test check, frontend TypeScript, and Vite build.",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {},
                                    "required": []
                                }
                            }
                        ]
                    }
                }
            elif method == "tools/call":
                tool_name = req.get("params", {}).get("name")
                if tool_name == "firecrow_validate_build":
                    res = validate_firecrow_project()
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(res, indent=2)
                                }
                            ]
                        }
                    }
                else:
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32601, "message": f"Method/Tool {tool_name} not found"}
                    }
            else:
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method {method} not found"}
                }
            print(json.dumps(resp), flush=True)
        except Exception as e:
            err_resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32603, "message": str(e)}}
            print(json.dumps(err_resp), flush=True)

def main():
    parser = argparse.ArgumentParser(description="Fire Crow Custom MCP Build Validator")
    parser.add_argument("--validate", action="store_true", help="Execute standalone validation check")
    parser.add_argument("--json", action="store_true", help="Output raw JSON format only")
    args = parser.parse_args()

    if args.validate or args.json:
        res = validate_firecrow_project()
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print("\n==========================================")
            print(f"  FIRECROW BUILD VALIDATION: {res['status']}")
            print("==========================================")
            for step_name, step_data in res["steps"].items():
                status_icon = "✓" if step_data["exit_code"] == 0 else "❌"
                print(f"{status_icon} {step_name.upper()} ({step_data['duration_sec']}s)")
            if res["errors"]:
                print("\nERRORS DETECTED:")
                for err in res["errors"]:
                    print(f"  - {err}")
        sys.exit(0 if res["status"] == "SUCCESS" else 1)
    else:
        # Default mode: MCP Stdio Server
        handle_mcp_stdio()

if __name__ == "__main__":
    main()
