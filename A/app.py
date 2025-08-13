"""
OWASP Top 10 2021 - Vulnerability Examples
Educational purposes only - demonstrates common web security issues
"""

from flask import Flask, request, jsonify, session
import hashlib
import pickle
import yaml
import requests
import logging
import jwt

app = Flask(__name__)

# ============================================================================
# A01: Broken Access Control (CWE-200, CWE-201, CWE-285, CWE-639)
# ============================================================================

@app.route('/api/admin/users', methods=['GET'])
def broken_access_control_1():
    # VULNERABLE - No access control check
    # BAD: Any user can access admin endpoint
    return jsonify(db.get_all_users())  # Exposes all user data!

@app.route('/api/account/<account_id>', methods=['PUT'])
def broken_access_control_2(account_id):
    # VULNERABLE - IDOR (Insecure Direct Object Reference)
    # BAD: No ownership verification
    new_balance = request.json.get('balance')
    db.update_account(account_id, balance=new_balance)  # Can modify any account!
    return jsonify({"updated": account_id})

@app.route('/api/download', methods=['GET'])
def path_traversal():
    # VULNERABLE - Path traversal
    # BAD: No path validation
    filename = request.args.get('file')
    return open(f'/files/{filename}').read()  # Can use ../../etc/passwd


# ============================================================================
# A02: Cryptographic Failures (CWE-259, CWE-327, CWE-331)
# ============================================================================

def weak_password_storage():
    # VULNERABLE - Weak hashing
    def store_password(password):
        # BAD: MD5 for password hashing
        hashed = hashlib.md5(password.encode()).hexdigest()
        db.save_password(hashed)  # Easily crackable!

def hardcoded_encryption_key():
    # VULNERABLE - Hardcoded key
    class Encryptor:
        # BAD: Key in source code
        SECRET_KEY = "my_super_secret_key_12345"
        
        def encrypt(self, data):
            return encrypt_aes(data, self.SECRET_KEY)

def insecure_random():
    # VULNERABLE - Predictable randomness
    import random
    def generate_token():
        # BAD: Not cryptographically secure
        token = random.randint(100000, 999999)  # Predictable!
        return str(token)


# ============================================================================
# A04: Insecure Design (CWE-209, CWE-256, CWE-501)
# ============================================================================

@app.route('/api/reset-password', methods=['POST'])
def insecure_password_reset():
    # VULNERABLE - Insecure design pattern
    email = request.json.get('email')
    # BAD: Reveals user existence
    if not db.user_exists(email):
        return jsonify({"error": "User not found"}), 404  # Information disclosure!
    
    # BAD: Weak reset token
    reset_token = hashlib.md5(email.encode()).hexdigest()[:6]
    return jsonify({"token": reset_token})

@app.route('/api/transfer', methods=['POST'])
def missing_rate_limit():
    # VULNERABLE - No rate limiting by design
    # BAD: Can be called unlimited times
    amount = request.json.get('amount')
    to_account = request.json.get('to')
    
    # No checking for repeated transfers!
    process_transfer(amount, to_account)
    return jsonify({"status": "success"})

def trust_boundary_violation():
    # VULNERABLE - Trusting client-side data
    def process_discount(order_data):
        # BAD: Accepting discount from client
        discount = order_data.get('discount_percentage', 0)
        final_price = price * (1 - discount/100)  # Client controls discount!
        return final_price


# ============================================================================
# A05: Security Misconfiguration (CWE-16, CWE-611, CWE-614)
# ============================================================================

# VULNERABLE - Debug mode enabled
app.config['DEBUG'] = True  # Stack traces exposed!
app.config['SECRET_KEY'] = 'dev'  # Weak secret!

@app.route('/api/error', methods=['GET'])
def verbose_errors():
    # VULNERABLE - Detailed error messages
    try:
        result = dangerous_operation()
    except Exception as e:
        # BAD: Full stack trace to user
        return jsonify({
            "error": str(e),
            "traceback": traceback.format_exc(),
            "database_path": db.connection_string  # Info leak!
        }), 500

def xxe_vulnerability():
    # VULNERABLE - XXE enabled
    import xml.etree.ElementTree as ET
    def parse_xml(xml_string):
        # BAD: External entities not disabled
        root = ET.fromstring(xml_string)  # XXE vulnerability!
        return root


# ============================================================================
# A07: Identification and Authentication Failures (CWE-287, CWE-384, CWE-522)
# ============================================================================

@app.route('/api/login', methods=['POST'])
def weak_authentication():
    # VULNERABLE - Weak session management
    username = request.json.get('username')
    password = request.json.get('password')
    
    # BAD: Weak password policy
    if len(password) >= 4:  # Only 4 chars required!
        # BAD: Session fixation
        session['user'] = username
        session['logged_in'] = True
        # No session regeneration!
        return jsonify({"status": "logged in"})

def weak_jwt_implementation():
    # VULNERABLE - JWT misuse
    def create_token(user_id):
        # BAD: Weak secret
        token = jwt.encode(
            {'user_id': user_id},
            'secret',  # Weak secret!
            algorithm='HS256'
        )
        return token

@app.route('/api/2fa', methods=['POST'])
def weak_2fa():
    # VULNERABLE - Bypassable 2FA
    code = request.json.get('code')
    skip_2fa = request.json.get('skip_2fa')
    
    # BAD: Can bypass 2FA
    if skip_2fa:
        return jsonify({"authenticated": True})  # 2FA bypassed!
    
    # BAD: No rate limiting on attempts
    if code == stored_2fa_code:
        return jsonify({"authenticated": True})


# ============================================================================
# A08: Software and Data Integrity Failures (CWE-345, CWE-494, CWE-829)
# ============================================================================

@app.route('/api/deserialize', methods=['POST'])
def insecure_deserialization():
    # VULNERABLE - Pickle deserialization
    data = request.get_data()
    # BAD: Deserializing untrusted data
    obj = pickle.loads(data)  # RCE vulnerability!
    return jsonify({"processed": True})

@app.route('/api/update', methods=['POST'])
def unsigned_update():
    # VULNERABLE - No integrity check
    update_url = request.json.get('update_url')
    # BAD: No signature verification
    update_file = requests.get(update_url).content
    install_update(update_file)  # Could be malicious!

def untrusted_sources():
    # VULNERABLE - Using untrusted CDN
    def load_javascript():
        # BAD: Loading from untrusted source
        script_url = "http://random-cdn.com/jquery.js"
        return f'<script src="{script_url}"></script>'  # Supply chain attack!


# ============================================================================
# A09: Security Logging and Monitoring Failures (CWE-223, CWE-532, CWE-778)
# ============================================================================

@app.route('/api/login', methods=['POST'])
def insufficient_logging():
    # VULNERABLE - Poor logging
    username = request.json.get('username')
    password = request.json.get('password')
    
    if authenticate(username, password):
        # BAD: Not logging successful login
        return jsonify({"status": "success"})
    else:
        # BAD: No failed login monitoring
        return jsonify({"status": "failed"})
    # No security events logged!

def sensitive_data_in_logs():
    # VULNERABLE - Logging sensitive data
    def process_payment(card_number, cvv):
        # BAD: Logging sensitive info
        logging.info(f"Payment: card={card_number}, cvv={cvv}")  # PCI violation!
        return process_transaction(card_number)

@app.route('/api/admin/delete', methods=['DELETE'])
def unmonitored_critical_action():
    # VULNERABLE - Critical action not logged
    user_id = request.json.get('user_id')
    # BAD: No audit trail for deletion
    db.delete_user(user_id)  # No logging!
    return jsonify({"deleted": user_id})


# ============================================================================
# A10: Server-Side Request Forgery (SSRF) (CWE-918)
# ============================================================================

@app.route('/api/fetch', methods=['POST'])
def ssrf_vulnerability():
    # VULNERABLE - Unvalidated URL fetch
    url = request.json.get('url')
    # BAD: No URL validation
    response = requests.get(url)  # Can access internal services!
    return response.content

@app.route('/api/webhook', methods=['POST'])
def webhook_ssrf():
    # VULNERABLE - Webhook to arbitrary URL
    callback_url = request.json.get('webhook_url')
    # BAD: Sending internal data to any URL
    internal_data = get_sensitive_data()
    requests.post(callback_url, json=internal_data)  # Data exfiltration!
    return jsonify({"webhook": "sent"})

@app.route('/api/image', methods=['GET'])
def image_proxy_ssrf():
    # VULNERABLE - Image proxy SSRF
    image_url = request.args.get('url')
    # BAD: Can probe internal network
    # Attack: url=http://169.254.169.254/latest/meta-data/
    img = requests.get(image_url).content
    return img, 200, {'Content-Type': 'image/jpeg'}