"""
Payload Simulator - Executes attack payloads in isolated sandboxes
"""
import docker
import tempfile
import os
import json
import time
from typing import Dict, Optional
from datetime import datetime
import re


class PayloadSimulator:
    """Simulate attack payloads against shadow application"""
    
    def __init__(self, docker_client=None):
        self.docker_client = docker_client or docker.from_env()
        self.timeout_seconds = 300  # 5 minutes max
        self.shadow_app_image = "cerberus-shadow-app:latest"
    
    def simulate(self, payload: Dict, shadow_app_ref: str = "main") -> Dict:
        """
        Simulate payload execution in sandbox
        
        Args:
            payload: Payload dict with type, value, location
            shadow_app_ref: Git reference for shadow app (commit/branch)
            
        Returns:
            Simulation result dict with verdict, severity, evidence
        """
        print(f"[SIMULATOR] Starting simulation for {payload.get('type')} payload")
        
        start_time = time.time()
        
        try:
            # Provision sandbox
            sandbox = self._provision_sandbox()
            
            # Deploy shadow app
            self._deploy_shadow_app(sandbox, shadow_app_ref)
            
            # Inject test data
            self._seed_database(sandbox)
            
            # Execute payload
            result = self._execute_payload(sandbox, payload)
            
            # Analyze result
            verdict = self._analyze_result(result, payload)
            
            # Calculate severity
            severity = self._calculate_severity(verdict, payload)
            
            # Collect evidence
            evidence = self._collect_evidence(sandbox, result)
            
            # Generate reproduction steps
            repro_steps = self._generate_repro_steps(payload, shadow_app_ref)
            
            execution_time = int((time.time() - start_time) * 1000)
            
            return {
                "verdict": verdict,
                "severity": severity,
                "execution_time_ms": execution_time,
                "evidence": evidence,
                "reproduction_steps": repro_steps,
                "attack_type": payload.get("type"),
                "payload": payload,
                "timestamp": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            print(f"[SIMULATOR] Error: {e}")
            return {
                "verdict": "error",
                "severity": 0.0,
                "error": str(e),
                "execution_time_ms": int((time.time() - start_time) * 1000)
            }
        
        finally:
            # Always cleanup sandbox
            if 'sandbox' in locals():
                self._destroy_sandbox(sandbox)
    
    def _provision_sandbox(self) -> Dict:
        """Create isolated sandbox container"""
        print("[SIMULATOR] Provisioning sandbox...")
        
        # Create isolated network
        network_name = f"sandbox_{int(time.time())}"
        network = self.docker_client.networks.create(
            network_name,
            driver="bridge",
            internal=True,  # No external access
            labels={"cerberus": "sandbox"}
        )
        
        # Start shadow app container
        container = self.docker_client.containers.run(
            "python:3.11-slim",  # Base image (in production: use custom shadow app image)
            command="sleep 300",  # Keep alive for 5 minutes
            detach=True,
            network=network_name,
            mem_limit="512m",
            cpu_period=100000,
            cpu_quota=50000,  # 0.5 CPU
            security_opt=["no-new-privileges"],
            cap_drop=["ALL"],
            read_only=False,  # Need write for app
            tmpfs={'/tmp': 'size=100M'},
            labels={"cerberus": "sandbox"}
        )
        
        # Wait for container to be ready
        time.sleep(2)
        
        print(f"[SIMULATOR] Sandbox provisioned: {container.id[:12]}")
        
        return {
            "container": container,
            "network": network,
            "id": container.id[:12]
        }
    
    def _deploy_shadow_app(self, sandbox: Dict, ref: str):
        """Deploy shadow application in sandbox"""
        container = sandbox["container"]
        
        # In production: clone shadow app repo and deploy
        # For demo: create a simple vulnerable Flask app
        
        app_code = '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

# Initialize database
conn = sqlite3.connect('/tmp/test.db')
c = conn.cursor()
c.execute("CREATE TABLE users (id INTEGER, name TEXT, email TEXT)")
c.execute("INSERT INTO users VALUES (1, 'Admin', 'admin@example.com')")
c.execute("INSERT INTO users VALUES (2, 'User', 'user@example.com')")
conn.commit()
conn.close()

@app.route('/api/v1/users')
def get_users():
    user_id = request.args.get('id', '')
    
    # Vulnerable to SQL injection
    conn = sqlite3.connect('/tmp/test.db')
    c = conn.cursor()
    
    if user_id:
        query = f"SELECT * FROM users WHERE id = {user_id}"  # VULNERABLE!
    else:
        query = "SELECT * FROM users"
    
    try:
        c.execute(query)
        results = c.fetchall()
        conn.close()
        return {"users": [{"id": r[0], "name": r[1], "email": r[2]} for r in results]}
    except Exception as e:
        conn.close()
        return {"error": str(e)}, 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
'''
        
        # Copy app to container
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(app_code)
            app_file = f.name
        
        try:
            # Install Flask
            container.exec_run("pip install flask", detach=False)
            
            # Copy app file
            with open(app_file, 'rb') as f:
                container.put_archive('/tmp', [(os.path.basename(app_file), f.read())])
            
            # Start app in background
            container.exec_run(
                f"python /tmp/{os.path.basename(app_file)}",
                detach=True
            )
            
            # Wait for app to start
            time.sleep(3)
            
            print("[SIMULATOR] Shadow app deployed")
        
        finally:
            os.unlink(app_file)
    
    def _seed_database(self, sandbox: Dict):
        """Inject synthetic test data"""
        # Data is created in _deploy_shadow_app for this demo
        print("[SIMULATOR] Database seeded with test data")
    
    def _execute_payload(self, sandbox: Dict, payload: Dict) -> Dict:
        """Execute the attack payload"""
        container = sandbox["container"]
        payload_type = payload.get("type", "unknown")
        payload_value = payload.get("value", "")
        
        print(f"[SIMULATOR] Executing {payload_type} payload...")
        
        if payload_type == "sql_injection":
            # Test SQL injection
            cmd = f"curl -s 'http://localhost:5000/api/v1/users?id={payload_value}'"
        
        elif payload_type == "xss":
            # Test XSS (not applicable for API, but log it)
            cmd = f"curl -s 'http://localhost:5000/api/v1/users?name={payload_value}'"
        
        elif payload_type == "command_injection":
            # Test command injection
            cmd = f"curl -s -d 'cmd={payload_value}' http://localhost:5000/api/exec"
        
        else:
            # Generic test
            cmd = "curl -s http://localhost:5000/api/v1/users"
        
        # Execute in container
        exec_result = container.exec_run(cmd, demux=True)
        
        stdout = exec_result.output[0].decode() if exec_result.output[0] else ""
        stderr = exec_result.output[1].decode() if exec_result.output[1] else ""
        
        return {
            "exit_code": exec_result.exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "payload_type": payload_type
        }
    
    def _analyze_result(self, result: Dict, payload: Dict) -> str:
        """
        Analyze execution result to determine if exploit succeeded
        
        Returns: "exploit_possible" or "exploit_improbable"
        """
        payload_type = payload.get("type", "unknown")
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        exit_code = result.get("exit_code", 0)
        
        # SQL Injection detection
        if payload_type == "sql_injection":
            # Check if query returned unexpected data
            if "admin@example.com" in stdout.lower() or "user@example.com" in stdout.lower():
                # Data was extracted
                if "OR" in payload.get("value", "").upper() or "UNION" in payload.get("value", "").upper():
                    return "exploit_possible"
            
            # Check for SQL errors (indicates injection attempt worked)
            if "syntax error" in stderr.lower() or "sqlite" in stderr.lower():
                return "exploit_possible"
        
        # XSS detection
        elif payload_type == "xss":
            # Check if script tag was reflected
            if "<script" in stdout:
                return "exploit_possible"
        
        # Command injection detection
        elif payload_type == "command_injection":
            # Check if command executed
            if exit_code == 0 and stdout:
                return "exploit_possible"
        
        # Path traversal detection
        elif payload_type == "path_traversal":
            # Check if sensitive file was accessed
            if "root:" in stdout or "etc/passwd" in stdout:
                return "exploit_possible"
        
        # No exploitation detected
        return "exploit_improbable"
    
    def _calculate_severity(self, verdict: str, payload: Dict) -> float:
        """Calculate severity score (0-10)"""
        if verdict == "exploit_improbable":
            return 0.0
        
        # Base score by payload type
        severity_map = {
            "sql_injection": 9.0,
            "command_injection": 10.0,
            "xss": 7.0,
            "path_traversal": 8.0,
            "file_upload": 8.5,
            "xxe": 9.0,
        }
        
        base_score = severity_map.get(payload.get("type", ""), 5.0)
        
        # Adjust by confidence
        confidence = payload.get("confidence", 0.5)
        adjusted_score = base_score * confidence
        
        return min(10.0, adjusted_score)
    
    def _collect_evidence(self, sandbox: Dict, result: Dict) -> Dict:
        """Collect evidence from sandbox"""
        container = sandbox["container"]
        
        # Get logs
        logs = container.logs(tail=50).decode()
        
        # Get filesystem changes (if any)
        # In production: diff filesystem, check for backdoors
        
        evidence = {
            "container_id": sandbox["id"],
            "execution_result": result,
            "container_logs": logs[-500:],  # Last 500 chars
            "exploitation_confirmed": result.get("verdict") == "exploit_possible"
        }
        
        return evidence
    
    def _generate_repro_steps(self, payload: Dict, ref: str) -> list:
        """Generate steps to reproduce the exploit"""
        steps = [
            f"Deploy shadow app from ref: {ref}",
            "Seed database with test data",
            f"Send request with payload: {payload.get('type')}",
            f"Payload value: {payload.get('value', '')}",
            "Observe response for unauthorized data access or errors",
            "Check logs for exploitation evidence"
        ]
        
        return steps
    
    def _destroy_sandbox(self, sandbox: Dict):
        """Destroy sandbox and cleanup"""
        try:
            container = sandbox["container"]
            network = sandbox["network"]
            
            print(f"[SIMULATOR] Destroying sandbox {sandbox['id']}...")
            
            # Stop and remove container
            container.stop(timeout=5)
            container.remove(force=True)
            
            # Remove network
            network.remove()
            
            print(f"[SIMULATOR] Sandbox {sandbox['id']} destroyed")
        
        except Exception as e:
            print(f"[SIMULATOR] Error destroying sandbox: {e}")
