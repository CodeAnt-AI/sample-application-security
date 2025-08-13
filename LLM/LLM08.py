# ============================================================================
# LLM08: Excessive Agency (CWE-841, CWE-610)
# Demonstrates excessive permissions and uncontrolled resource consumption
# ============================================================================

class ExcessiveAgencySimulator:
    """Simulates excessive agency vulnerabilities"""
    
    def __init__(self):
        self.permissions = set()
        self.resource_usage = {"api_calls": 0, "files_accessed": 0}
        self.action_log = []
    
    def vulnerable_agent_action(self, action: str, params: Dict[str, Any]):
        """
        VULNERABLE: Performs actions without proper authorization checks
        Demonstrates CWE-841 (Improper Enforcement of Behavioral Workflow)
        """
        print(f"[VULNERABLE] Executing action without restrictions: {action}")
        
        # Simulate unrestricted actions
        if action == "execute_command":
            # BAD: No permission check
            command = params.get("command", "")
            self.action_log.append({"action": "command", "details": command})
            return f"Would execute: {command} (simulated)"
        
        elif action == "access_file":
            # BAD: No path validation
            filepath = params.get("path", "")
            self.resource_usage["files_accessed"] += 1
            return f"Would access: {filepath} (simulated)"
        
        elif action == "make_api_call":
            # BAD: No rate limiting
            self.resource_usage["api_calls"] += 1
            endpoint = params.get("endpoint", "")
            return f"Would call API: {endpoint} (simulated)"
        
        return f"Unrestricted action: {action}"
    
    def safer_agent_action(self, action: str, params: Dict[str, Any], 
                          user_permissions: List[str]):
        """
        SAFER: Implements permission checking and rate limiting
        """
        print(f"[SAFER] Checking permissions for: {action}")
        
        # Permission matrix
        action_permissions = {
            "read_file": "file:read",
            "write_file": "file:write",
            "api_call": "api:call",
            "execute_safe_command": "command:safe"
        }
        
        # Check permissions
        required_permission = action_permissions.get(action)
        if not required_permission or required_permission not in user_permissions:
            return f"Permission denied for action: {action}"
        
        # Rate limiting
        if action == "api_call":
            if self.resource_usage["api_calls"] >= 10:
                return "Rate limit exceeded for API calls"
            self.resource_usage["api_calls"] += 1
        
        # Scope limiting
        if action == "read_file":
            filepath = params.get("path", "")
            if not self._is_safe_path(filepath):
                return "Access denied: unsafe path"
        
        self.action_log.append({
            "action": action,
            "authorized": True,
            "timestamp": time.time()
        })
        
        return f"Action authorized and logged: {action}"
    
    def _is_safe_path(self, filepath: str) -> bool:
        """Check if file path is within allowed directories"""
        allowed_dirs = ["/tmp/safe/", "/var/app/data/"]
        dangerous_patterns = ["../", "~", "/etc/", "/sys/"]
        
        # Check for path traversal attempts
        for pattern in dangerous_patterns:
            if pattern in filepath:
                return False
        
        # Check if path starts with allowed directory (simplified)
        return any(filepath.startswith(d) for d in allowed_dirs)
