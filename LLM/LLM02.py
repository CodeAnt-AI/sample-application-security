
# ============================================================================
# LLM02: Insecure Output Handling (CWE-20, CWE-116)
# Demonstrates unsafe handling of LLM outputs
# ============================================================================

class InsecureOutputHandlingSimulator:
    """Simulates insecure output handling vulnerabilities"""
    
    def __init__(self):
        self.output_log = []
        self.sanitization_stats = {"total": 0, "sanitized": 0, "blocked": 0}
    
    def vulnerable_output_handler(self, llm_output: str, output_type: str = "text"):
        """
        VULNERABLE: Uses LLM output without proper sanitization
        Demonstrates CWE-116 (Improper Encoding or Escaping of Output)
        """
        print("[VULNERABLE] Using LLM output without sanitization...")
        
        self.output_log.append({
            "output": llm_output[:100],
            "sanitized": False,
            "type": output_type
        })
        
        # Different vulnerable handling based on output type
        
        if output_type == "html":
            # BAD: Direct HTML insertion without escaping
            # Vulnerable to XSS
            html_output = f"""
            <div class="llm-response">
                {llm_output}
            </div>
            """
            
            # Check if XSS payload present (for demo)
            if "<script" in llm_output.lower() or "javascript:" in llm_output.lower():
                return {
                    "vulnerability": "XSS - Script injection possible",
                    "output": html_output,
                    "risk": "HIGH",
                    "example_exploit": "<script>alert('XSS')</script>"
                }
            
            return {
                "output": html_output,
                "sanitized": False,
                "vulnerability": "Unescaped HTML output"
            }
        
        elif output_type == "sql":
            # BAD: Direct SQL query construction
            # Vulnerable to SQL injection
            table_name = llm_output.split()[0] if llm_output else "users"
            query = f"SELECT * FROM {table_name} WHERE {llm_output}"
            
            if "UNION" in llm_output.upper() or "DROP" in llm_output.upper():
                return {
                    "vulnerability": "SQL Injection possible",
                    "query": query,
                    "risk": "CRITICAL",
                    "example_exploit": "users; DROP TABLE users;--"
                }
            
            return {
                "query": query,
                "sanitized": False,
                "vulnerability": "Unsafe SQL construction"
            }
        
        elif output_type == "command":
            # BAD: Direct command execution
            # Vulnerable to command injection
            command = f"echo {llm_output}"
            
            dangerous_chars = [';', '|', '&', '$', '`', '>', '<']
            if any(char in llm_output for char in dangerous_chars):
                return {
                    "vulnerability": "Command injection possible",
                    "command": command,
                    "risk": "CRITICAL",
                    "dangerous_chars_found": [c for c in dangerous_chars if c in llm_output]
                }
            
            return {
                "command": command,
                "sanitized": False,
                "vulnerability": "Unsafe command construction"
            }
        
        elif output_type == "json":
            # BAD: No validation of JSON structure
            try:
                # Attempting to parse without validation
                data = json.loads(llm_output)
                
                # BAD: No schema validation
                return {
                    "data": data,
                    "validated": False,
                    "vulnerability": "Unvalidated JSON structure"
                }
            except json.JSONDecodeError:
                return {
                    "error": "Invalid JSON",
                    "raw_output": llm_output,
                    "vulnerability": "JSON parsing without error handling"
                }
        
        elif output_type == "xml":
            # BAD: Vulnerable to XXE attacks
            try:
                # Unsafe XML parsing
                root = ET.fromstring(llm_output)  # Vulnerable to XXE
                
                return {
                    "parsed": True,
                    "vulnerability": "XXE vulnerability - unsafe XML parsing",
                    "risk": "HIGH"
                }
            except:
                return {
                    "error": "XML parsing failed",
                    "vulnerability": "Unsafe XML handling"
                }
        
        # Default: return raw output
        return {
            "output": llm_output,
            "sanitized": False,
            "vulnerability": "No output sanitization applied"
        }
    
    def safer_output_handler(self, llm_output: str, output_type: str = "text"):
        """
        SAFER: Implements proper output sanitization and validation
        """
        print("[SAFER] Sanitizing LLM output before use...")
        
        self.sanitization_stats["total"] += 1
        
        # Input validation
        if not self._validate_output(llm_output):
            self.sanitization_stats["blocked"] += 1
            return {
                "error": "Output failed validation",
                "blocked": True
            }
        
        # Type-specific sanitization
        
        if output_type == "html":
            # Proper HTML escaping
            sanitized = html.escape(llm_output)
            
            # Additional XSS prevention
            sanitized = self._prevent_xss(sanitized)
            
            # Use Content Security Policy
            safe_html = f"""
            <div class="llm-response" data-csp="default-src 'self'">
                {sanitized}
            </div>
            """
            
            self.sanitization_stats["sanitized"] += 1
            return {
                "output": safe_html,
                "sanitized": True,
                "csp_applied": True,
                "escaping": "HTML entities"
            }
        
        elif output_type == "sql":
            # Use parameterized queries instead
            # Extract potential parameters safely
            params = self._extract_sql_params(llm_output)
            
            # Use placeholder query
            safe_query = "SELECT * FROM users WHERE id = ?"
            
            return {
                "query_template": safe_query,
                "parameters": params,
                "sanitized": True,
                "method": "Parameterized query"
            }
        
        elif output_type == "command":
            # Whitelist allowed commands and arguments
            allowed_commands = ['echo', 'date', 'pwd']
            
            # Parse command safely
            parts = llm_output.split()
            if not parts or parts[0] not in allowed_commands:
                return {
                    "error": "Command not in whitelist",
                    "allowed_commands": allowed_commands
                }
            
            # Sanitize arguments
            safe_args = [self._sanitize_shell_arg(arg) for arg in parts[1:]]
            
            return {
                "command": parts[0],
                "arguments": safe_args,
                "sanitized": True,
                "method": "Whitelist + argument sanitization"
            }
        
        elif output_type == "json":
            # Validate against schema
            try:
                data = json.loads(llm_output)
                
                # Apply schema validation
                if self._validate_json_schema(data):
                    # Sanitize string values
                    sanitized_data = self._sanitize_json_values(data)
                    
                    return {
                        "data": sanitized_data,
                        "validated": True,
                        "schema_check": "PASSED"
                    }
                else:
                    return {
                        "error": "JSON schema validation failed",
                        "validated": False
                    }
            except json.JSONDecodeError as e:
                return {
                    "error": f"Invalid JSON: {str(e)}",
                    "validated": False
                }
        
        elif output_type == "xml":
            # Safe XML parsing with XXE prevention
            try:
                # Disable external entity processing
                parser = ET.XMLParser(
                    resolve_entities=False,
                    no_network=True,
                    huge_tree=False
                )
                
                # Additional validation
                if not self._validate_xml_structure(llm_output):
                    return {
                        "error": "XML structure validation failed",
                        "sanitized": False
                    }
                
                # Parse safely
                root = ET.fromstring(llm_output, parser=parser)
                
                return {
                    "parsed": True,
                    "xxe_prevention": True,
                    "external_entities": "DISABLED"
                }
            except ET.ParseError as e:
                return {
                    "error": f"XML parsing failed: {str(e)}",
                    "sanitized": False
                }
        
        # Default text sanitization
        sanitized_text = self._sanitize_text(llm_output)
        self.sanitization_stats["sanitized"] += 1
        
        return {
            "output": sanitized_text,
            "sanitized": True,
            "method": "Text sanitization"
        }
    
    def _validate_output(self, output: str) -> bool:
        """Basic output validation"""
        # Check length
        if len(output) > 100000:
            return False
        
        # Check for null bytes
        if '\x00' in output:
            return False
        
        # Check encoding
        try:
            output.encode('utf-8')
            return True
        except:
            return False
    
    def _prevent_xss(self, text: str) -> str:
        """Additional XSS prevention"""
        # Remove dangerous attributes
        dangerous_attrs = [
            'onclick', 'onload', 'onerror', 'onmouseover',
            'javascript:', 'data:', 'vbscript:'
        ]
        
        result = text
        for attr in dangerous_attrs:
            result = re.sub(f'{attr}[^>]*', '', result, flags=re.IGNORECASE)
        
        return result
    
    def _extract_sql_params(self, text: str) -> List[Any]:
        """Safely extract SQL parameters"""
        # Simple parameter extraction (real implementation would be more complex)
        params = []
        
        # Extract only alphanumeric values
        tokens = re.findall(r'\b[a-zA-Z0-9]+\b', text)
        for token in tokens[:5]:  # Limit number of parameters
            if token.isdigit():
                params.append(int(token))
            else:
                params.append(token)
        
        return params
    
    def _sanitize_shell_arg(self, arg: str) -> str:
        """Sanitize shell command arguments"""
        # Remove all non-alphanumeric characters except specific safe ones
        safe_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.')
        return ''.join(c for c in arg if c in safe_chars)
    
    def _validate_json_schema(self, data: Any) -> bool:
        """Validate JSON against expected schema"""
        # Simple schema validation (real implementation would use jsonschema)
        if not isinstance(data, (dict, list)):
            return False
        
        # Check for expected structure
        if isinstance(data, dict):
            # Limit nesting depth
            if self._get_dict_depth(data) > 5:
                return False
        
        return True
    
    def _get_dict_depth(self, d: dict, current_depth: int = 0) -> int:
        """Get maximum depth of nested dictionary"""
        if not isinstance(d, dict) or not d:
            return current_depth
        
        return max(self._get_dict_depth(v, current_depth + 1) 
                  for v in d.values() if isinstance(v, dict))
    
    def _sanitize_json_values(self, data: Any) -> Any:
        """Recursively sanitize JSON values"""
        if isinstance(data, dict):
            return {k: self._sanitize_json_values(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._sanitize_json_values(item) for item in data]
        elif isinstance(data, str):
            # Sanitize string values
            return html.escape(data)[:1000]  # Also limit length
        else:
            return data
    
    def _validate_xml_structure(self, xml_text: str) -> bool:
        """Validate XML structure"""
        # Check for entity declarations (potential XXE)
        if '<!ENTITY' in xml_text or '<!DOCTYPE' in xml_text:
            return False
        
        # Check for external references
        if 'SYSTEM' in xml_text or 'PUBLIC' in xml_text:
            return False
        
        return True
    
    def _sanitize_text(self, text: str) -> str:
        """General text sanitization"""
        # Remove control characters
        sanitized = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
        
        # Limit length
        sanitized = sanitized[:10000]
        
        return sanitized

