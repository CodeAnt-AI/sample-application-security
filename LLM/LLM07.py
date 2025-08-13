
"""
Educational simulations of OWASP Top 10 LLM vulnerabilities.
FOR SECURITY TESTING AND EDUCATIONAL PURPOSES ONLY.
These examples demonstrate vulnerability concepts - use responsibly in controlled environments.
"""

import json
import subprocess
import pickle
import hashlib
import time
from typing import Dict, Any, List
import re

# ============================================================================
# LLM07: Insecure Plugin Design (CWE-749, CWE-94)
# Demonstrates unsafe plugin execution and injection vulnerabilities
# ============================================================================

class InsecurePluginSimulator:
    """Simulates insecure plugin design vulnerabilities"""
    
    def __init__(self):
        self.plugins = {}
        self.execution_log = []
    
    def vulnerable_plugin_executor(self, plugin_code: str, user_input: str):
        """
        VULNERABLE: Executes plugin code without proper sandboxing
        Demonstrates CWE-94 (Code Injection)
        """
        print("[VULNERABLE] Executing unsandboxed plugin code...")
        
        # Simulate vulnerable dynamic code execution
        try:
            # BAD PRACTICE: Direct eval with user input
            context = {"user_input": user_input, "result": None}
            exec(plugin_code, context)  # Vulnerable to code injection
            
            self.execution_log.append({
                "timestamp": time.time(),
                "plugin_code": plugin_code[:100],
                "status": "executed"
            })
            
            return context.get("result", "No result")
        except Exception as e:
            return f"Plugin execution failed: {e}"
    
    def safer_plugin_executor(self, plugin_name: str, user_input: str):
        """
        SAFER: Uses predefined plugins with input validation
        """
        print("[SAFER] Using validated plugin system...")
        
        # Whitelist of allowed plugins
        allowed_plugins = {
            "calculator": self._safe_calculator,
            "text_processor": self._safe_text_processor
        }
        
        if plugin_name not in allowed_plugins:
            return "Plugin not authorized"
        
        # Sanitize user input
        sanitized_input = self._sanitize_input(user_input)
        
        return allowed_plugins[plugin_name](sanitized_input)
    
    def _sanitize_input(self, user_input: str) -> str:
        """Basic input sanitization"""
        # Remove potentially dangerous characters/patterns
        dangerous_patterns = [';', '&&', '||', '`', '$', '\\']
        sanitized = user_input
        for pattern in dangerous_patterns:
            sanitized = sanitized.replace(pattern, '')
        return sanitized[:1000]  # Limit length
    
    def _safe_calculator(self, expression: str) -> str:
        """Safe calculator plugin with restricted operations"""
        # Only allow basic math operations
        allowed_chars = set('0123456789+-*/()., ')
        if all(c in allowed_chars for c in expression):
            try:
                result = eval(expression)  # Still risky but limited
                return f"Result: {result}"
            except:
                return "Invalid expression"
        return "Expression contains disallowed characters"
    
    def _safe_text_processor(self, text: str) -> str:
        """Safe text processing plugin"""
        return f"Processed text (length: {len(text)}): {text[:100]}"