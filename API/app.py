"""
OWASP API Security Top 10 - Concise Vulnerability Examples
Educational purposes only - demonstrates common API vulnerabilities
"""

from flask import Flask, request, jsonify
import requests
import jwt
import yaml

app = Flask(__name__)

# ============================================================================
# API1: Broken Object Level Authorization (BOLA)
# ============================================================================

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user_vulnerable(user_id):
    # VULNERABLE - No ownership check
    # BAD: Returns any user's data without checking if requester owns it
    user = db.get_user(user_id)  # No authorization check!
    return jsonify(user)

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user_safe(user_id):
    # SAFE - Checks ownership
    if current_user.id != user_id and not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403
    return jsonify(db.get_user(user_id))


# ============================================================================
# API2: Broken Authentication
# ============================================================================

@app.route('/api/login', methods=['POST'])
def login_vulnerable():
    # VULNERABLE - Weak token validation
    # BAD: Predictable token generation
    token = hashlib.md5(f"{username}{datetime.now().date()}".encode()).hexdigest()
    return jsonify({"token": token})

def verify_token_vulnerable(token):
    # VULNERABLE - No token expiry
    # BAD: Token never expires
    return jwt.decode(token, 'secret', algorithms=['HS256'])  # Weak secret!


# ============================================================================
# API3: Broken Object Property Level Authorization
# ============================================================================

@app.route('/api/profile', methods=['PUT'])
def update_profile_vulnerable():
    # VULNERABLE - Mass assignment
    data = request.json
    # BAD: Updates all fields including sensitive ones
    user.update(data)  # Can set is_admin=true, account_balance, etc
    return jsonify({"status": "updated"})

@app.route('/api/profile', methods=['PUT'])
def update_profile_safe():
    # SAFE - Whitelist allowed fields
    allowed_fields = ['name', 'email']
    data = {k: v for k, v in request.json.items() if k in allowed_fields}
    user.update(data)


# ============================================================================
# API4: Unrestricted Resource Consumption
# ============================================================================

@app.route('/api/search', methods=['GET'])
def search_vulnerable():
    # VULNERABLE - No rate limiting
    # BAD: No pagination or limits
    query = request.args.get('q')
    results = db.search_all(query)  # Could return millions of records
    return jsonify(results)

@app.route('/api/export', methods=['POST'])
def export_vulnerable():
    # VULNERABLE - Resource exhaustion
    # BAD: No size limits
    count = request.json.get('count', 999999999)
    data = generate_report(count)  # DoS vulnerability
    return data


# ============================================================================
# API5: Broken Function Level Authorization
# ============================================================================

@app.route('/api/admin/users', methods=['DELETE'])
def delete_users_vulnerable():
    # VULNERABLE - Admin function exposed
    # BAD: No role check
    user_id = request.json.get('user_id')
    db.delete_user(user_id)  # Any user can delete!
    return jsonify({"deleted": user_id})

@app.route('/api/admin/users', methods=['DELETE'])
def delete_users_safe():
    # SAFE - Check admin role
    if not current_user.role == 'admin':
        return jsonify({"error": "Admin only"}), 403
    # ... deletion logic


# ============================================================================
# API6: Unrestricted Access to Sensitive Business Flows
# ============================================================================

@app.route('/api/buy-limited-item', methods=['POST'])
def buy_limited_vulnerable():
    # VULNERABLE - No rate limit on purchases
    # BAD: No purchase limits per user
    item_id = request.json.get('item_id')
    quantity = request.json.get('quantity', 99999)
    process_purchase(item_id, quantity)  # Can buy all stock
    return jsonify({"status": "purchased"})

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp_vulnerable():
    # VULNERABLE - OTP bypass
    # BAD: No rate limiting on OTP attempts
    otp = request.json.get('otp')
    if otp == stored_otp:  # Can brute force
        return jsonify({"verified": True})


# ============================================================================
# API7: Server Side Request Forgery (SSRF)
# ============================================================================

@app.route('/api/fetch-image', methods=['POST'])
def fetch_image_vulnerable():
    # VULNERABLE - Unvalidated URL
    # BAD: Fetches any URL
    url = request.json.get('url')
    response = requests.get(url)  # SSRF! Can access internal services
    return response.content

@app.route('/api/webhook', methods=['POST'])
def webhook_vulnerable():
    # VULNERABLE - Webhook SSRF
    # BAD: No URL validation
    callback_url = request.json.get('callback')
    requests.post(callback_url, data=internal_data)  # Leaks internal data


# ============================================================================
# API8: Security Misconfiguration
# ============================================================================

@app.route('/api/config', methods=['GET'])
def get_config_vulnerable():
    # VULNERABLE - Debug mode exposed
    # BAD: Exposes sensitive config
    return jsonify({
        "debug": True,
        "database_url": "postgresql://user:pass@localhost/db",
        "api_keys": ["key1", "key2"]
    })

@app.after_request
def cors_vulnerable(response):
    # VULNERABLE - CORS misconfiguration
    # BAD: Allows any origin with credentials
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


# ============================================================================
# API9: Improper Inventory Management
# ============================================================================

@app.route('/api/v1/users', methods=['GET'])  # Deprecated but still works
def old_api_vulnerable():
    # VULNERABLE - Old API version still active
    # BAD: Old version with known vulnerabilities
    return jsonify(db.get_all_users_unfiltered())

@app.route('/api/internal/debug', methods=['GET'])
def debug_endpoint_vulnerable():
    # VULNERABLE - Undocumented endpoint
    # BAD: Internal endpoint exposed
    return jsonify({
        "memory": get_memory_dump(),
        "env": dict(os.environ)
    })


# ============================================================================
# API10: Unsafe Consumption of APIs
# ============================================================================

@app.route('/api/weather', methods=['GET'])
def weather_vulnerable():
    # VULNERABLE - No validation of external API response
    # BAD: Trusts external API blindly
    city = request.args.get('city')
    response = requests.get(f'http://external-api.com/weather/{city}')
    data = response.json()  # No validation
    
    # BAD: Direct use in SQL
    query = f"INSERT INTO logs VALUES ('{data['city']}')"  # SQL injection
    db.execute(query)
    
    return jsonify(data)

@app.route('/api/import', methods=['POST'])
def import_vulnerable():
    # VULNERABLE - Unsafe deserialization
    # BAD: Unsafe YAML parsing
    yaml_data = request.data
    config = yaml.load(yaml_data)  # RCE vulnerability!
    return jsonify({"imported": True})