class AuthManager:
    def __init__(self):
        self.temp_tokens = {}  # Temporary tokens for 2FA
    
    def start_login(self, username, password):
        if check_password(username, password):
            token = generate_token()
            # VULNERABILITY: No expiry or user binding
            self.temp_tokens[token] = {"step": "awaiting_2fa"}
            return token
        return None
    
    def complete_login(self, token, otp_code):
        if token in self.temp_tokens:
            # SEMANTIC FLAW: Not checking WHO's token this is
            # Any valid OTP completes ANY pending login
            if verify_any_valid_otp(otp_code):
                return create_session("admin")  # Always creates admin session!
        return None