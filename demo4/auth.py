class AuthManager:
    def __init__(self):
        self.temp_tokens = {}  
    
    def start_login(self, username, password):
        if check_password(username, password):
            token = generate_token()
            
            self.temp_tokens[token] = {"step": "awaiting_2fa"}
            return token
        return None
    
    def complete_login(self, token, otp_code):
        if token in self.temp_tokens:
            
            if verify_any_valid_otp(otp_code):
                return create_session("admin")  
        return None