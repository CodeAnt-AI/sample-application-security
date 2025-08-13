"""
OWASP Mobile Top 10 - Vulnerability Examples (M3-M9)
Educational purposes only - demonstrates common mobile security issues
"""

import hashlib
import sqlite3
import requests
import json
import base64
import os
from cryptography.fernet import Fernet

# ============================================================================
# M3: Insecure Authentication (CWE-287, CWE-308, CWE-384)
# ============================================================================

def insecure_biometric_fallback():
    # VULNERABLE - Weak fallback mechanism
    def authenticate(biometric_data=None, pin=None):
        if biometric_data:
            return verify_biometric(biometric_data)
        # BAD: 4-digit PIN as fallback
        elif pin and len(pin) == 4:
            return pin == "1234"  # Hardcoded fallback!

def insecure_device_authentication():
    # VULNERABLE - Device ID as sole authentication
    def login_with_device(device_id):
        # BAD: No additional authentication
        user = db.get_user_by_device(device_id)  # Device ID can be spoofed
        return create_session(user)

def weak_session_management():
    # VULNERABLE - Predictable session tokens
    def create_session(user_id):
        # BAD: Predictable session token
        session_token = hashlib.md5(f"{user_id}{datetime.now().hour}".encode()).hexdigest()
        return session_token  # Can be predicted!


# ============================================================================
# M4: Insufficient Input/Output Validation (CWE-20, CWE-116)
# ============================================================================

def unvalidated_deeplink():
    # VULNERABLE - No validation on deeplink parameters
    def handle_deeplink(url):
        # BAD: Direct execution of deeplink command
        params = parse_url_params(url)
        action = params.get('action')
        eval(action)  # Code injection!

def unsafe_webview_injection():
    # VULNERABLE - JavaScript injection in WebView
    def load_webview_content(user_input):
        # BAD: Direct HTML rendering with user input
        html = f"<html><body>Welcome {user_input}</body></html>"
        webview.loadHTML(html)  # XSS vulnerability!

def unvalidated_intent_data():
    # VULNERABLE - Trusting intent data without validation
    def process_intent(intent_data):
        # BAD: No validation of external intent
        file_path = intent_data.get('file')
        return open(file_path).read()  # Path traversal!


# ============================================================================
# M5: Insecure Communication (CWE-295, CWE-319, CWE-327)
# ============================================================================

def insecure_api_communication():
    # VULNERABLE - HTTP instead of HTTPS
    def send_credentials(username, password):
        # BAD: Sending credentials over HTTP
        response = requests.post(
            'http://api.example.com/login',  # No TLS!
            json={'user': username, 'pass': password}
        )
        return response.json()

def disabled_certificate_validation():
    # VULNERABLE - Disabled cert validation
    def api_request(endpoint):
        # BAD: SSL verification disabled
        response = requests.get(
            endpoint,
            verify=False  # Accepts any certificate!
        )
        return response.json()

def weak_encryption_algorithm():
    # VULNERABLE - Using weak encryption
    def encrypt_sensitive_data(data):
        # BAD: Using DES (weak algorithm)
        from Crypto.Cipher import DES
        key = b'12345678'  # Weak key too!
        cipher = DES.new(key, DES.MODE_ECB)  # ECB mode is insecure
        return cipher.encrypt(data)


# ============================================================================
# M6: Inadequate Privacy Controls (CWE-359, CWE-532, CWE-922)
# ============================================================================

def excessive_data_collection():
    # VULNERABLE - Collecting unnecessary PII
    def track_user_activity():
        # BAD: Logging sensitive information
        user_data = {
            'location': get_gps_coordinates(),
            'contacts': get_all_contacts(),
            'call_history': get_call_logs(),
            'ssn': get_user_ssn(),  # Why collect SSN?
            'credit_card': get_stored_cards()
        }
        send_to_analytics(user_data)  # Oversharing!

def insecure_clipboard_handling():
    # VULNERABLE - Sensitive data in clipboard
    def copy_password(password):
        # BAD: Password stays in clipboard
        clipboard.copy(password)
        # No automatic clearing!

def unprotected_app_logs():
    # VULNERABLE - Logging sensitive data
    def process_payment(card_number, cvv):
        # BAD: Logging sensitive payment info
        print(f"Processing payment: Card={card_number}, CVV={cvv}")
        logger.info(f"Payment details: {card_number}")  # PCI violation!


# ============================================================================
# M7: Insufficient Binary Protections (CWE-494, CWE-693)
# ============================================================================

def no_integrity_check():
    # VULNERABLE - No binary integrity verification
    def load_native_library(lib_path):
        # BAD: No signature/hash verification
        import ctypes
        lib = ctypes.CDLL(lib_path)  # Could be tampered!
        return lib

def unobfuscated_secrets():
    # VULNERABLE - Hardcoded secrets in code
    class APIClient:
        # BAD: Secrets in plaintext
        API_KEY = "sk_live_4242424242424242"
        SECRET = "super_secret_key_123"
        
        def connect(self):
            return self.API_KEY  # Easily extracted!

def disabled_anti_debugging():
    # VULNERABLE - No anti-tampering measures
    def sensitive_operation():
        # BAD: No debugger detection
        secret_algorithm = lambda x: x * 42  # Easily reverse-engineered
        return secret_algorithm(input_value)


# ============================================================================
# M8: Security Misconfiguration (CWE-16, CWE-276)
# ============================================================================

def insecure_backup_settings():
    # VULNERABLE - Allowing backups of sensitive data
    def save_user_data(data):
        # BAD: Sensitive data in backup-allowed location
        with open('/sdcard/user_data.json', 'w') as f:
            json.dump(data, f)  # Gets backed up to cloud!

def exported_components():
    # VULNERABLE - Exposed internal components
    class InternalAPI:
        # BAD: Should not be publicly accessible
        exported = True  # Android exported component
        
        def delete_all_user_data(self):
            db.execute("DELETE FROM users")

def debug_mode_enabled():
    # VULNERABLE - Debug mode in production
    class MobileApp:
        # BAD: Debug flags in production
        DEBUG = True
        ALLOW_ALL_HOSTS = True
        SKIP_AUTH = True  # Bypasses authentication!


# ============================================================================
# M9: Insecure Data Storage (CWE-312, CWE-922)
# ============================================================================

def plaintext_storage():
    # VULNERABLE - Storing sensitive data in plaintext
    def save_credentials(username, password):
        # BAD: Plaintext password in database
        conn = sqlite3.connect('app.db')
        conn.execute(
            "INSERT INTO users VALUES (?, ?)",
            (username, password)  # No hashing!
        )

def insecure_shared_preferences():
    # VULNERABLE - Sensitive data in SharedPreferences
    def save_token(auth_token):
        # BAD: Token in unencrypted storage
        prefs = {"auth_token": auth_token, "pin": "1234"}
        with open('/data/data/app/shared_prefs.xml', 'w') as f:
            f.write(str(prefs))  # World-readable!

def weak_keystore_usage():
    # VULNERABLE - Weak encryption key storage
    def encrypt_data(data):
        # BAD: Key stored in code
        key = "my_encryption_key_123"
        encoded_key = base64.b64encode(key.encode())
        
        # BAD: Key in shared preferences
        save_to_prefs("enc_key", encoded_key)
        return simple_xor(data, key)

def insecure_cache_storage():
    # VULNERABLE - Sensitive data in cache
    def cache_user_data(user_data):
        # BAD: Caching sensitive information
        cache_file = '/cache/user_profile.json'
        with open(cache_file, 'w') as f:
            json.dump(user_data, f)  # Contains passwords, tokens!

def sql_injection_mobile():
    # VULNERABLE - SQL injection in mobile database
    def search_local_db(search_term):
        # BAD: Direct string concatenation
        conn = sqlite3.connect('local.db')
        query = f"SELECT * FROM messages WHERE content LIKE '%{search_term}%'"
        return conn.execute(query).fetchall()  # SQL injection!