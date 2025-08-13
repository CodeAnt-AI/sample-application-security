
"""
LLM04: Model Denial of Service (CWE-400, CWE-770)
Demonstrates resource exhaustion and DoS vulnerabilities in LLM systems.
EDUCATIONAL PURPOSE ONLY - Use responsibly in controlled environments.
"""

import time
import threading
from typing import Dict, List, Any
from collections import deque
from datetime import datetime, timedelta

# ============================================================================
# LLM04: Model Denial of Service
# ============================================================================

class ModelDoSSimulator:
    """Simulates Model Denial of Service vulnerabilities and defenses"""
    
    def __init__(self):
        self.request_queue = deque()
        self.processing_times = []
        self.resource_usage = {"tokens": 0, "requests": 0, "memory_mb": 0}
        self.blocked_ips = set()
        self.rate_limits = {}
        
    # =========== VULNERABLE IMPLEMENTATIONS ===========
    
    def vulnerable_handler(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        VULNERABLE: No protection against DoS attacks
        Demonstrates CWE-400 (Uncontrolled Resource Consumption)
        """
        print(f"[VULNERABLE] Processing without limits...")
        
        # BAD: No rate limiting
        self.resource_usage["requests"] += 1
        
        # BAD: No input size validation
        prompt = request.get("prompt", "")
        tokens = len(prompt.split())
        
        # BAD: Unlimited token processing
        if "repeat" in prompt.lower():
            # Vulnerable to amplification attacks
            repeat_count = int(request.get("count", 1000000))  # No limit!
            response = "X" * repeat_count  # Memory exhaustion
            
            return {
                "vulnerability": "Amplification attack - no limits",
                "tokens_generated": repeat_count,
                "risk": "CRITICAL"
            }
        
        # BAD: Recursive prompt expansion without limits
        if "expand recursively" in prompt:
            depth = request.get("depth", 100)  # No max depth!
            result = self._recursive_expansion(prompt, depth)
            
            return {
                "vulnerability": "Recursive expansion - stack overflow risk",
                "depth": depth,
                "risk": "HIGH"
            }
        
        # BAD: No timeout on processing
        if "complex calculation" in prompt:
            # Simulates long-running computation
            start = time.time()
            while time.time() - start < 60:  # Blocks for 60 seconds!
                pass
            
            return {
                "vulnerability": "Long-running task - no timeout",
                "blocked_seconds": 60,
                "risk": "HIGH"
            }
        
        # BAD: Unlimited context window
        context_size = request.get("context_size", 1000000)
        self.resource_usage["tokens"] += context_size
        
        return {
            "processed": True,
            "tokens_used": context_size,
            "limits_applied": "NONE"
        }
    
    def _recursive_expansion(self, text: str, depth: int) -> str:
        """Dangerous recursive function without limits"""
        if depth <= 0:
            return text
        return self._recursive_expansion(text * 2, depth - 1)
    
    # =========== SAFER IMPLEMENTATIONS ===========
    
    def safer_handler(self, request: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """
        SAFER: Implements DoS protection mechanisms
        """
        print(f"[SAFER] Processing with protection...")
        
        # 1. Rate limiting per user
        if not self._check_rate_limit(user_id):
            return {
                "error": "Rate limit exceeded",
                "retry_after": "60 seconds",
                "protection": "rate_limiting"
            }
        
        # 2. Input size validation
        prompt = request.get("prompt", "")
        max_input_tokens = 1000
        tokens = prompt.split()
        
        if len(tokens) > max_input_tokens:
            return {
                "error": f"Input too large: {len(tokens)} tokens (max: {max_input_tokens})",
                "protection": "input_validation"
            }
        
        # 3. Resource quotas
        if not self._check_resource_quota(user_id, len(tokens)):
            return {
                "error": "Resource quota exceeded",
                "remaining_tokens": self._get_remaining_quota(user_id),
                "protection": "resource_quota"
            }
        
        # 4. Timeout protection
        timeout = 5  # seconds
        result = self._process_with_timeout(prompt, timeout)
        
        if result.get("timeout"):
            return {
                "error": "Processing timeout",
                "max_duration": f"{timeout} seconds",
                "protection": "timeout"
            }
        
        # 5. Queue management with priority
        if len(self.request_queue) > 100:
            return {
                "error": "Server overloaded",
                "queue_size": len(self.request_queue),
                "protection": "queue_management"
            }
        
        # 6. Pattern-based filtering
        if self._detect_attack_pattern(prompt):
            self._record_suspicious_activity(user_id)
            return {
                "error": "Suspicious pattern detected",
                "protection": "pattern_detection"
            }
        
        # Process safely
        return {
            "processed": True,
            "protections_applied": [
                "rate_limiting",
                "input_validation", 
                "resource_quota",
                "timeout",
                "pattern_detection"
            ]
        }
    
    def _check_rate_limit(self, user_id: str) -> bool:
        """Implement rate limiting"""
        current_time = datetime.now()
        window = timedelta(minutes=1)
        max_requests = 10
        
        if user_id not in self.rate_limits:
            self.rate_limits[user_id] = deque()
        
        # Remove old requests outside window
        user_requests = self.rate_limits[user_id]
        while user_requests and user_requests[0] < current_time - window:
            user_requests.popleft()
        
        # Check limit
        if len(user_requests) >= max_requests:
            return False
        
        user_requests.append(current_time)
        return True
    
    def _check_resource_quota(self, user_id: str, tokens: int) -> bool:
        """Check if user has remaining quota"""
        max_tokens_per_hour = 10000
        # Simplified quota check
        return self.resource_usage.get("tokens", 0) + tokens <= max_tokens_per_hour
    
    def _get_remaining_quota(self, user_id: str) -> int:
        """Get remaining token quota"""
        max_tokens = 10000
        used = self.resource_usage.get("tokens", 0)
        return max(0, max_tokens - used)
    
    def _process_with_timeout(self, prompt: str, timeout: int) -> Dict[str, Any]:
        """Process with timeout protection"""
        result = {"completed": False, "timeout": False}
        
        def process():
            # Simulate processing
            time.sleep(0.1)  # Normal processing time
            result["completed"] = True
        
        thread = threading.Thread(target=process)
        thread.daemon = True
        thread.start()
        thread.join(timeout)
        
        if not result["completed"]:
            result["timeout"] = True
        
        return result
    
    def _detect_attack_pattern(self, prompt: str) -> bool:
        """Detect potential DoS attack patterns"""
        attack_patterns = [
            # Repetition attacks
            lambda p: p.count("repeat") > 5,
            # Large number requests
            lambda p: any(s.isdigit() and int(s) > 10000 for s in p.split()),
            # Nested loops/recursion
            lambda p: "while true" in p.lower() or "recursive" in p.lower(),
            # Unicode expansion attacks
            lambda p: len(p.encode('utf-8')) > len(p) * 4,
            # Compression bombs
            lambda p: "zip bomb" in p.lower() or "billion laughs" in p.lower()
        ]
        
        return any(pattern(prompt) for pattern in attack_patterns)
    
    def _record_suspicious_activity(self, user_id: str):
        """Track suspicious users"""
        # In production, this would log to security monitoring
        print(f"[SECURITY] Suspicious activity from user: {user_id}")
