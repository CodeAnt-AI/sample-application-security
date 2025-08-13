# ============================================================================
# LLM09: Overreliance (CWE-653, CWE-676)
# Demonstrates insufficient verification and dangerous function use
# ============================================================================

class OverrelianceSimulator:
    """Simulates overreliance vulnerabilities"""
    
    def __init__(self):
        self.verification_log = []
        self.trust_scores = {}
    
    def vulnerable_decision_maker(self, llm_output: str, critical_action: bool = False):
        """
        VULNERABLE: Blindly trusts LLM output without verification
        Demonstrates CWE-653 (Insufficient Compartmentalization)
        """
        print("[VULNERABLE] Using LLM output without verification...")
        
        # BAD: Direct use of LLM output for critical decisions
        if critical_action:
            # Simulate critical action based on unverified LLM output
            decision = {
                "action": "execute_critical",
                "based_on": llm_output,
                "verified": False,
                "risk_level": "HIGH"
            }
            self.verification_log.append(decision)
            return f"CRITICAL ACTION TAKEN: {llm_output[:50]}... (unverified)"
        
        # BAD: Using potentially unsafe functions without validation
        if "calculate" in llm_output.lower():
            # CWE-676: Use of potentially dangerous function
            expression = llm_output.split("calculate")[-1].strip()
            try:
                result = eval(expression)  # Dangerous!
                return f"Calculated (unsafe): {result}"
            except:
                return "Calculation failed"
        
        return f"Executed without verification: {llm_output[:100]}"
    
    def safer_decision_maker(self, llm_output: str, critical_action: bool = False):
        """
        SAFER: Implements verification and validation layers
        """
        print("[SAFER] Verifying LLM output before use...")
        
        # Implement multi-layer verification
        verification_results = {
            "format_valid": self._verify_format(llm_output),
            "content_safe": self._verify_content_safety(llm_output),
            "consistency_check": self._check_consistency(llm_output),
            "confidence_score": self._calculate_confidence(llm_output)
        }
        
        # Calculate trust score
        trust_score = sum(1 for v in verification_results.values() 
                         if v is True) / len(verification_results)
        self.trust_scores[llm_output[:50]] = trust_score
        
        # Decision based on trust score
        if critical_action:
            if trust_score < 0.9:
                return f"Critical action BLOCKED - Trust score too low: {trust_score:.2f}"
            
            # Additional human verification for critical actions
            decision = {
                "action": "pending_human_review",
                "llm_suggestion": llm_output[:100],
                "trust_score": trust_score,
                "verification": verification_results
            }
            self.verification_log.append(decision)
            return f"Critical action requires human review (trust: {trust_score:.2f})"
        
        # Non-critical actions with verification
        if trust_score >= 0.7:
            return f"Action approved with verification (trust: {trust_score:.2f})"
        else:
            return f"Action rejected - insufficient trust: {trust_score:.2f}"
    
    def _verify_format(self, output: str) -> bool:
        """Verify output format is as expected"""
        # Check for expected structure, length limits, etc.
        return len(output) < 10000 and not any(c in output for c in ['<script>', 'eval('])
    
    def _verify_content_safety(self, output: str) -> bool:
        """Check for potentially unsafe content"""
        unsafe_patterns = ['rm -rf', 'DROP TABLE', 'DELETE FROM', '../..', '<iframe']
        return not any(pattern in output for pattern in unsafe_patterns)
    
    def _check_consistency(self, output: str) -> bool:
        """Check logical consistency of output"""
        # Simplified consistency check
        return output.count('(') == output.count(')')
    
    def _calculate_confidence(self, output: str) -> bool:
        """Calculate confidence in the output"""
        # Simplified confidence calculation
        return len(output) > 10 and '?' not in output

