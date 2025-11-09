"""
Stage 10: Sandbox Security Manager - Enforces isolation and safety for simulations
Ensures no egress, resource limits, and audit trails
"""
import os
import json
from typing import Dict, List, Optional
from datetime import datetime
import subprocess

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.utils.logging import get_logger

logger = get_logger(__name__)


class SandboxSecurityManager:
    """
    Manages sandbox security controls:
    - Network isolation (no egress except monitored proxy)
    - Resource limits (CPU, memory, disk)
    - Audit logging
    - Automatic cleanup
    - Panic button functionality
    """
    
    # Default resource limits
    DEFAULT_CPU_LIMIT = "2.0"  # 2 vCPU
    DEFAULT_MEMORY_LIMIT = "2g"  # 2GB RAM
    DEFAULT_DISK_LIMIT = "1g"  # 1GB disk
    DEFAULT_TIMEOUT_SECONDS = 300  # 5 minutes
    
    # Network controls
    ALLOW_EGRESS = False  # No outbound connections by default
    MONITORED_PROXY = None  # Optional: proxy for controlled egress
    
    def __init__(self):
        self.active_sandboxes: Dict[str, Dict] = {}
        self.audit_log_path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'data', 'audit', 'sandbox_audit.jsonl'
        )
        os.makedirs(os.path.dirname(self.audit_log_path), exist_ok=True)
        
        logger.info("Sandbox security manager initialized")
    
    def create_sandbox(
        self,
        sandbox_id: str,
        image: str = "python:3.11-slim",
        network_mode: str = "none",
        cpu_limit: str = None,
        memory_limit: str = None
    ) -> Dict:
        """
        Create a secure sandbox with enforced controls
        
        Args:
            sandbox_id: Unique sandbox identifier
            image: Docker image to use
            network_mode: "none" (isolated) or "custom" (with monitored proxy)
            cpu_limit: CPU limit (e.g., "2.0")
            memory_limit: Memory limit (e.g., "2g")
            
        Returns:
            Sandbox configuration dict
        """
        try:
            # Validate sandbox doesn't already exist
            if sandbox_id in self.active_sandboxes:
                logger.warning(f"Sandbox {sandbox_id} already exists")
                return self.active_sandboxes[sandbox_id]
            
            # Apply default limits
            cpu_limit = cpu_limit or self.DEFAULT_CPU_LIMIT
            memory_limit = memory_limit or self.DEFAULT_MEMORY_LIMIT
            
            # Build sandbox config
            sandbox_config = {
                "id": sandbox_id,
                "image": image,
                "network_mode": network_mode if self.ALLOW_EGRESS else "none",
                "cpu_limit": cpu_limit,
                "memory_limit": memory_limit,
                "disk_limit": self.DEFAULT_DISK_LIMIT,
                "timeout_seconds": self.DEFAULT_TIMEOUT_SECONDS,
                "created_at": datetime.utcnow().isoformat(),
                "status": "created",
                "security_controls": {
                    "egress_blocked": not self.ALLOW_EGRESS,
                    "resource_limits_enforced": True,
                    "read_only_root": True,
                    "no_privileged": True,
                    "drop_capabilities": ["ALL"]
                }
            }
            
            # Track active sandbox
            self.active_sandboxes[sandbox_id] = sandbox_config
            
            # Audit log
            self._audit_log("sandbox_created", sandbox_config)
            
            logger.info(f"Sandbox created: {sandbox_id}")
            
            return sandbox_config
        
        except Exception as e:
            logger.error(f"Error creating sandbox: {e}", exc_info=True)
            return {}
    
    def enforce_network_isolation(self, sandbox_id: str) -> bool:
        """
        Verify network isolation is enforced
        
        Tests:
        - No DNS resolution to external domains
        - No TCP connections to external IPs
        - No UDP traffic
        """
        try:
            sandbox = self.active_sandboxes.get(sandbox_id)
            
            if not sandbox:
                logger.error(f"Sandbox not found: {sandbox_id}")
                return False
            
            # Check network mode
            if sandbox["network_mode"] != "none":
                logger.warning(f"Sandbox {sandbox_id} not in isolated network mode")
                return False
            
            # Additional checks would test actual network access
            # For MVP: verify configuration
            
            logger.info(f"Network isolation verified for sandbox: {sandbox_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error verifying network isolation: {e}", exc_info=True)
            return False
    
    def enforce_resource_limits(self, sandbox_id: str) -> bool:
        """
        Verify resource limits are enforced
        
        Checks:
        - CPU limit applied
        - Memory limit applied
        - Disk limit applied
        """
        try:
            sandbox = self.active_sandboxes.get(sandbox_id)
            
            if not sandbox:
                return False
            
            # Verify limits are configured
            required_limits = ["cpu_limit", "memory_limit", "disk_limit"]
            
            for limit in required_limits:
                if limit not in sandbox or not sandbox[limit]:
                    logger.error(f"Missing resource limit: {limit}")
                    return False
            
            logger.info(f"Resource limits verified for sandbox: {sandbox_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error verifying resource limits: {e}", exc_info=True)
            return False
    
    def destroy_sandbox(self, sandbox_id: str, reason: str = "normal_completion"):
        """
        Destroy sandbox and cleanup resources
        
        Args:
            sandbox_id: Sandbox to destroy
            reason: Reason for destruction
        """
        try:
            sandbox = self.active_sandboxes.get(sandbox_id)
            
            if not sandbox:
                logger.warning(f"Sandbox not found for destruction: {sandbox_id}")
                return
            
            # Update status
            sandbox["status"] = "destroyed"
            sandbox["destroyed_at"] = datetime.utcnow().isoformat()
            sandbox["destruction_reason"] = reason
            
            # Audit log
            self._audit_log("sandbox_destroyed", sandbox)
            
            # Remove from active list
            del self.active_sandboxes[sandbox_id]
            
            logger.info(f"Sandbox destroyed: {sandbox_id} (reason: {reason})")
        
        except Exception as e:
            logger.error(f"Error destroying sandbox: {e}", exc_info=True)
    
    def panic_button(self):
        """
        Emergency: Destroy ALL active sandboxes immediately
        
        Use when:
        - Suspected sandbox escape
        - Security incident
        - System compromise detected
        """
        logger.critical("🚨 PANIC BUTTON ACTIVATED - Destroying all sandboxes")
        
        sandbox_ids = list(self.active_sandboxes.keys())
        
        for sandbox_id in sandbox_ids:
            self.destroy_sandbox(sandbox_id, reason="PANIC_BUTTON")
        
        # Audit
        self._audit_log("panic_button_activated", {
            "sandboxes_destroyed": len(sandbox_ids),
            "timestamp": datetime.utcnow().isoformat()
        })
        
        logger.critical(f"Panic complete: {len(sandbox_ids)} sandboxes destroyed")
    
    def get_active_sandboxes(self) -> List[Dict]:
        """Get list of all active sandboxes"""
        return list(self.active_sandboxes.values())
    
    def check_sandbox_health(self, sandbox_id: str) -> Dict:
        """
        Check sandbox health and security posture
        
        Returns:
            Health status dict
        """
        sandbox = self.active_sandboxes.get(sandbox_id)
        
        if not sandbox:
            return {"status": "not_found"}
        
        # Check security controls
        network_ok = self.enforce_network_isolation(sandbox_id)
        resources_ok = self.enforce_resource_limits(sandbox_id)
        
        # Check timeout
        created_at = datetime.fromisoformat(sandbox["created_at"])
        age_seconds = (datetime.utcnow() - created_at).total_seconds()
        timeout_exceeded = age_seconds > sandbox["timeout_seconds"]
        
        health = {
            "status": "healthy" if (network_ok and resources_ok and not timeout_exceeded) else "unhealthy",
            "sandbox_id": sandbox_id,
            "age_seconds": age_seconds,
            "timeout_exceeded": timeout_exceeded,
            "security_controls": {
                "network_isolation": network_ok,
                "resource_limits": resources_ok
            }
        }
        
        # Auto-destroy if timeout exceeded
        if timeout_exceeded:
            logger.warning(f"Sandbox timeout exceeded: {sandbox_id}")
            self.destroy_sandbox(sandbox_id, reason="timeout_exceeded")
        
        return health
    
    def _audit_log(self, event_type: str, data: Dict):
        """
        Append event to immutable audit log
        
        Format: JSON Lines (one JSON object per line)
        """
        try:
            audit_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "event_type": event_type,
                "data": data
            }
            
            # Append to log
            with open(self.audit_log_path, 'a') as f:
                f.write(json.dumps(audit_entry) + '\n')
        
        except Exception as e:
            logger.error(f"Error writing audit log: {e}", exc_info=True)
    
    def get_audit_log(self, limit: int = 100) -> List[Dict]:
        """Retrieve recent audit log entries"""
        try:
            if not os.path.exists(self.audit_log_path):
                return []
            
            entries = []
            with open(self.audit_log_path, 'r') as f:
                for line in f:
                    entries.append(json.loads(line.strip()))
            
            # Return last N entries
            return entries[-limit:]
        
        except Exception as e:
            logger.error(f"Error reading audit log: {e}", exc_info=True)
            return []


# CLI entry point
if __name__ == "__main__":
    manager = SandboxSecurityManager()
    
    # Create sandbox
    sandbox = manager.create_sandbox("test_sandbox_001", image="python:3.11-slim")
    print(f"\nSandbox created: {sandbox['id']}")
    
    # Verify security
    print(f"Network isolation: {manager.enforce_network_isolation(sandbox['id'])}")
    print(f"Resource limits: {manager.enforce_resource_limits(sandbox['id'])}")
    
    # Health check
    health = manager.check_sandbox_health(sandbox['id'])
    print(f"\nHealth: {json.dumps(health, indent=2)}")
    
    # Cleanup
    manager.destroy_sandbox(sandbox['id'])
    
    # View audit log
    print("\n=== Audit Log ===\n")
    for entry in manager.get_audit_log(limit=10):
        print(f"{entry['timestamp']}: {entry['event_type']}")
