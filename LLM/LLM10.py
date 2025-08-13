# ============================================================================
# LLM10: Model Theft (CWE-311, CWE-522)
# Demonstrates model extraction and insufficient credential protection
# ============================================================================

class ModelTheftSimulator:
    """Simulates model theft vulnerabilities"""
    
    def __init__(self):
        self.model_queries = []
        self.extraction_attempts = 0
        self.api_keys = {}
    
    def vulnerable_model_access(self, query: str, include_metadata: bool = True):
        """
        VULNERABLE: Exposes model internals and lacks query protection
        Demonstrates CWE-311 (Missing Encryption of Sensitive Data)
        """
        print("[VULNERABLE] Providing unrestricted model access...")
        
        # BAD: No rate limiting on queries
        self.model_queries.append(query)
        
        # BAD: Exposing model metadata
        if include_metadata:
            sensitive_info = {
                "model_version": "gpt-4-internal-v2",
                "training_data_hash": hashlib.md5(b"training_data").hexdigest(),
                "architecture": "transformer-xl-modified",
                "parameters": "175B",
                "fine_tuning_dataset": "proprietary_dataset_v3",
                "api_endpoint": "https://api.internal.com/v2/model"
            }
            
            return {
                "response": f"Model response to: {query}",
                "metadata": sensitive_info,  # BAD: Exposing internals
                "query_count": len(self.model_queries)
            }
        
        # BAD: No detection of extraction attempts
        if "extract" in query.lower() or "parameters" in query.lower():
            self.extraction_attempts += 1
            # Still provides response without protection
        
        return {"response": f"Unrestricted response to: {query}"}
    
    def vulnerable_credential_storage(self, api_key: str, user_id: str):
        """
        VULNERABLE: Stores credentials insecurely
        Demonstrates CWE-522 (Insufficiently Protected Credentials)
        """
        print("[VULNERABLE] Storing credentials insecurely...")
        
        # BAD: Storing API keys in plaintext
        self.api_keys[user_id] = api_key  # No encryption!
        
        # BAD: Weak hashing for verification
        weak_hash = hashlib.md5(api_key.encode()).hexdigest()
        
        return {
            "stored": True,
            "storage_method": "plaintext",
            "verification_hash": weak_hash
        }
    
    def safer_model_access(self, query: str, user_token: str):
        """
        SAFER: Implements protection against model extraction
        """
        print("[SAFER] Providing protected model access...")
        
        # Rate limiting
        recent_queries = [q for q in self.model_queries 
                         if time.time() - q.get('timestamp', 0) < 60]
        if len(recent_queries) >= 10:
            return {"error": "Rate limit exceeded", "retry_after": 60}
        
        # Detect extraction attempts
        extraction_patterns = [
            r'(extract|steal|copy).*model',
            r'show.*parameters',
            r'reveal.*architecture',
            r'training.*data',
            r'internal.*details'
        ]
        
        for pattern in extraction_patterns:
            if re.search(pattern, query.lower()):
                self.extraction_attempts += 1
                if self.extraction_attempts > 3:
                    return {"error": "Suspicious activity detected", "blocked": True}
                return {"warning": "Query pattern flagged for review"}
        
        # Watermarking responses
        response_id = hashlib.sha256(f"{query}{time.time()}".encode()).hexdigest()[:8]
        
        # Log query with protection
        self.model_queries.append({
            "timestamp": time.time(),
            "query_hash": hashlib.sha256(query.encode()).hexdigest(),
            "user_token_hash": hashlib.sha256(user_token.encode()).hexdigest(),
            "response_id": response_id
        })
        
        return {
            "response": f"Protected response to query",
            "response_id": response_id,  # For tracking potential theft
            "rate_limit_remaining": 10 - len(recent_queries)
        }
    
    def safer_credential_storage(self, api_key: str, user_id: str):
        """
        SAFER: Implements secure credential storage
        """
        print("[SAFER] Storing credentials securely...")
        
        # Use proper hashing for storage (simplified - use bcrypt/scrypt in production)
        import secrets
        
        # Generate salt
        salt = secrets.token_hex(16)
        
        # Strong hashing (simplified - use proper KDF in production)
        key_hash = hashlib.pbkdf2_hmac('sha256', 
                                       api_key.encode(), 
                                       salt.encode(), 
                                       100000)
        
        # Store hashed version only
        self.api_keys[user_id] = {
            "hash": key_hash.hex(),
            "salt": salt,
            "algorithm": "pbkdf2_sha256",
            "created": time.time()
        }
        
        return {
            "stored": True,
            "storage_method": "hashed",
            "algorithm": "pbkdf2_sha256"
        }
